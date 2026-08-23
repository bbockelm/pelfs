package webapi_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/webapi"
)

// The ordinary upload: one whole-file multipart POST, the bytes in the
// volume, the result the component reads its new id from, and no temp file
// left anywhere.
func TestUploadLandsTheFile(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "dir-0")

	body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"payload.bin", "the whole file"}})
	r := f.upload("/dir-0", body, ct)
	r.want(http.StatusOK)

	var out struct {
		Result webapi.UploadResult `json:"result"`
	}
	decodeInto(t, r.Body, &out)
	if out.Result.ID != "/dir-0/payload.bin" {
		t.Fatalf("result id %q, want /dir-0/payload.bin", out.Result.ID)
	}
	if out.Result.Size != int64(len("the whole file")) {
		t.Errorf("result size %d, want %d", out.Result.Size, len("the whole file"))
	}
	if got := f.read("/dir-0/payload.bin"); got != "the whole file" {
		t.Errorf("the uploaded file holds %q", got)
	}
	if left := f.parts("/dir-0"); len(left) != 0 {
		t.Errorf("a finished upload left %v behind", left)
	}
}

// The optional `name` field renames the upload, and it works whether it
// arrives BEFORE the file part or after: the final name is chosen once the
// whole body has been read, which it has to be anyway for the .pelfs-part
// rename.
func TestUploadNameOverride(t *testing.T) {
	for _, tc := range []struct{ name, order string }{
		{"the field before the file", "before"},
		{"the field after the file", "after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFix(t)
			f.dir(rootIno, "dir-0")
			var body, ct string
			if tc.order == "before" {
				body, ct = multipartBody(t, webapi.UploadField,
					[][2]string{{"sent-as.bin", "bytes"}},
					[2]string{webapi.NameField, "saved-as.bin"})
			} else {
				body, ct = multipartBodyFieldsLast(t, webapi.UploadField,
					[][2]string{{"sent-as.bin", "bytes"}},
					[2]string{webapi.NameField, "saved-as.bin"})
			}
			f.upload("/dir-0", body, ct).want(http.StatusOK)
			if !f.exists("/dir-0/saved-as.bin") {
				t.Errorf("the override name is not in the volume; the directory holds %v", f.names("/dir-0"))
			}
			if f.exists("/dir-0/sent-as.bin") {
				t.Error("the file landed under the browser's filename as well as the override")
			}
		})
	}
}

// Several files in one request get one result each, for the same reason a
// batch move does.
func TestUploadOfSeveralFiles(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "dir-0")
	body, ct := multipartBody(t, webapi.UploadField,
		[][2]string{{"one.bin", "1"}, {"two.bin", "22"}, {"three.bin", "333"}})
	r := f.upload("/dir-0", body, ct)
	r.want(http.StatusOK)
	var out struct {
		Result []webapi.UploadResult `json:"result"`
	}
	decodeInto(t, r.Body, &out)
	if len(out.Result) != 3 {
		t.Fatalf("three files produced %d results: %s", len(out.Result), r.Body)
	}
	for i, want := range []struct {
		id   string
		size int64
	}{{"/dir-0/one.bin", 1}, {"/dir-0/two.bin", 2}, {"/dir-0/three.bin", 3}} {
		if out.Result[i].ID != want.id || out.Result[i].Size != want.size {
			t.Errorf("result %d = %+v, want %s/%d", i, out.Result[i], want.id, want.size)
		}
	}
}

// THE STREAMING PROOF.
//
// The design's one non-negotiable implementation note is r.MultipartReader()
// rather than r.ParseMultipartForm(), because the latter buffers and then
// spools to a temp file — writing a 68 MB SIF to disk twice. "We used the
// right call" is not a testable claim, so three measurable consequences of it
// are tested instead, on a body larger than anything this package allocates:
//
//  1. PEAK HEAP does not grow with the body. A buffering implementation holds
//     the whole payload live at once; this one holds 32 KiB.
//  2. NO SINGLE WRITE to the volume is larger than the streaming buffer, so
//     the bytes really did arrive in chunks.
//  3. The volume received EXACTLY the payload's size in bytes, once.
//
// Plus TestNoParseMultipartFormAnywhere, which is the static half.
func TestUploadStreamsRatherThanBuffers(t *testing.T) {
	// The design's own reference file: docs/design-apptainer.md's SIF, the
	// size a physicist actually uploads.
	const size = 68_497_408
	// maxFootprint is what the peak may grow by, in absolute bytes rather
	// than as a fraction of the body, because the claim being tested is that
	// the footprint DOES NOT SCALE with the body. It has to stay far below
	// size or the test stops discriminating: a buffering implementation of a
	// 16 MB upload would fit inside a 16 MiB allowance, which is exactly why
	// the body here is the full reference size and not a convenient one.
	const maxFootprint = 16 << 20
	if testing.Short() {
		t.Skip("this proof needs a real 68 MB payload; the static half " +
			"(TestNoParseMultipartFormAnywhere) and the chunk-size half still run")
	}
	f := newFix(t)
	f.dir(rootIno, "dir-0")

	body, ct := bigMultipart(webapi.UploadField, "reference.sif", size)

	// Sample the heap while the upload runs. A post-hoc reading would miss
	// the peak entirely, which is the number that distinguishes streaming
	// from buffering.
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampling := make(chan struct{})
	go func() {
		defer close(sampling)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			for {
				old := peak.Load()
				if ms.HeapAlloc <= old || peak.CompareAndSwap(old, ms.HeapAlloc) {
					break
				}
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	var base runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&base)
	writtenBefore := f.cnt.written.Load()

	start := time.Now()
	r := f.uploadReader("/dir-0", body, ct)
	elapsed := time.Since(start)
	close(stop)
	<-sampling
	r.want(http.StatusOK)
	t.Logf("uploaded %d bytes in %s", size, elapsed)

	// 1. The peak.
	grew := int64(peak.Load()) - int64(base.HeapAlloc)
	if grew > maxFootprint {
		t.Errorf("peak heap grew by %d bytes while streaming a %d-byte upload. "+
			"A streaming upload's footprint does not scale with the body; this one did, "+
			"which is what ParseMultipartForm (or an io.ReadAll) looks like.", grew, size)
	}
	t.Logf("peak heap grew by %d bytes for a %d-byte body", grew, size)

	// 2. The chunks.
	if maxw := f.cnt.maxWrite.Load(); maxw > 64<<10 {
		t.Errorf("the largest single write to the volume was %d bytes; the streaming buffer is "+
			"32 KiB, so a write far larger than that means the body was assembled first", maxw)
	}

	// 3. Once, and all of it.
	if got := f.cnt.written.Load() - writtenBefore; got != size {
		t.Errorf("the volume received %d bytes for a %d-byte upload; twice the size is the "+
			"signature of a spool-then-copy", got, size)
	}

	// And the file is really the file: compared streaming, so the test does
	// not do the thing it is asserting the handler does not do.
	h, err := f.fs.OpenFile("/dir-0/reference.sif", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("opening the uploaded file: %v", err)
	}
	defer h.Close() //nolint:errcheck
	if err := comparePattern(h, size); err != nil {
		t.Errorf("the uploaded bytes are not the bytes that were sent: %v", err)
	}
	if left := f.parts("/dir-0"); len(left) != 0 {
		t.Errorf("the upload left %v behind", left)
	}
}

// The static half of the streaming proof. ParseMultipartForm is a one-line
// change with a whole-file-sized consequence, and the reviewer who would
// catch it is not always there.
func TestNoParseMultipartFormAnywhere(t *testing.T) {
	// The AST rather than a grep over the source, because the names being
	// banned are also the names this package's own comments have to use to
	// explain why they are banned. A selector expression is a call; a comment
	// is not.
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing this package: %v", err)
	}
	banned := map[string]string{
		"ParseMultipartForm": "it buffers the upload and spools the rest to a temp file",
		"FormFile":           "it calls ParseMultipartForm underneath",
		"MultipartForm":      "it is the field ParseMultipartForm fills in",
	}
	seen := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			seen++
			ast.Inspect(file, func(n ast.Node) bool {
				sel, isSel := n.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				if why, bad := banned[sel.Sel.Name]; bad {
					t.Errorf("%s uses %s, and %s — which writes a 68 MB SIF to disk twice. "+
						"Use r.MultipartReader(): docs/design-webui.md calls that the single most "+
						"important implementation note in the upload section.",
						filepath.Base(name), sel.Sel.Name, why)
				}
				return true
			})
		}
	}
	if seen == 0 {
		t.Fatal("no source files were scanned, so this proves nothing")
	}
}

// A .PELFS-PART MUST NOT SURVIVE A FAILED UPLOAD, and the final name must
// never appear for one. This is the durability requirement, not a tidiness
// one: the bytes are in the overlay the moment they are written, and the next
// checkpoint would publish a truncated file under the name the user believes
// is theirs.
func TestFailedUploadLeavesNothingBehind(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "dir-0")

	// A body that stops in the middle of the file part: the connection a
	// browser drops at 90% of a 68 MB SIF, in miniature.
	const boundary = "----pelfsTruncated"
	truncated := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"half.bin\"\r\n\r\n" +
		strings.Repeat("x", 4096) // and then nothing: no closing boundary
	r := f.upload("/dir-0", truncated, "multipart/form-data; boundary="+boundary)
	r.want(http.StatusBadRequest)

	if f.exists("/dir-0/half.bin") {
		t.Error("a truncated upload appeared under its final name; the next checkpoint would publish it")
	}
	if left := f.parts("/dir-0"); len(left) != 0 {
		t.Errorf("a failed upload left %v behind", left)
	}
	if names := f.names("/dir-0"); len(names) != 0 {
		t.Errorf("the directory is not empty after a failed upload: %v", names)
	}
}

// The name a browser sends is data, and a crafted one is the only way this
// route could be talked into writing outside the directory the id named.
func TestUploadRefusals(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "dir-0")
	f.mkdir(rootIno, "theirs", 0o555, f.they, f.thgr)
	f.text(rootIno, "afile.txt", "not a directory")

	t.Run("a filename that is a traversal", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"../../escaped.bin", "x"}})
		r := f.upload("/dir-0", body, ct)
		// path.Base reduces it to a name, which is then a perfectly legal
		// one; what matters is where it landed.
		r.want(http.StatusOK)
		if f.exists("/escaped.bin") {
			t.Error("an upload escaped the directory its id named")
		}
		if !f.exists("/dir-0/escaped.bin") {
			t.Errorf("the upload did not land in the named directory: %v", f.names("/dir-0"))
		}
	})
	t.Run("a filename that is only a traversal", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"..", "x"}})
		f.upload("/dir-0", body, ct).want(http.StatusBadRequest)
	})
	t.Run("a directory this session may not write", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"x.bin", "x"}})
		f.upload("/theirs", body, ct).want(http.StatusForbidden)
	})
	t.Run("a target that is not a directory", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"x.bin", "x"}})
		f.upload("/afile.txt", body, ct).want(http.StatusBadRequest)
	})
	t.Run("a target that is not there", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"x.bin", "x"}})
		f.upload("/nope", body, ct).want(http.StatusNotFound)
	})
	t.Run("a body that is not multipart", func(t *testing.T) {
		f.upload("/dir-0", `{"not":"multipart"}`, "application/json").want(http.StatusBadRequest)
	})
	t.Run("a multipart body with no file part", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField, nil, [2]string{webapi.NameField, "lonely"})
		f.upload("/dir-0", body, ct).want(http.StatusBadRequest)
	})
	t.Run("a form field larger than a form field has any business being", func(t *testing.T) {
		body, ct := multipartBody(t, webapi.UploadField,
			[][2]string{{"x.bin", "x"}}, [2]string{webapi.NameField, strings.Repeat("n", 8<<10)})
		f.upload("/dir-0", body, ct).want(http.StatusBadRequest)
	})
}

// An upload replaces an existing file, which is what a file manager does, and
// the replacement is atomic at the name: the old bytes are there until the
// rename.
func TestUploadReplacesAnExistingFile(t *testing.T) {
	f := newFix(t)
	d := f.dir(rootIno, "dir-0")
	f.text(d, "same.bin", "old bytes")
	body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"same.bin", "new bytes"}})
	f.upload("/dir-0", body, ct).want(http.StatusOK)
	if got := f.read("/dir-0/same.bin"); got != "new bytes" {
		t.Errorf("the file holds %q after being replaced", got)
	}
	if left := f.parts("/dir-0"); len(left) != 0 {
		t.Errorf("the replacement left %v behind", left)
	}
}

// ---- helpers -------------------------------------------------------------

// patternReader emits a deterministic pattern without holding it: the
// streaming test's body is 68 MB and the test must not be the thing that
// allocates it.
type patternReader struct {
	left int64
	off  int64
}

func (p *patternReader) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(b))
	if n > p.left {
		n = p.left
	}
	for i := int64(0); i < n; i++ {
		b[i] = patternByte(p.off + i)
	}
	p.off += n
	p.left -= n
	return int(n), nil
}

// patternByte is the payload: position-dependent, so a chunk written at the
// wrong offset is visible rather than being another copy of the same byte.
func patternByte(off int64) byte { return byte(off%251 + 1) }

// comparePattern reads r and reports the first byte that is not the pattern.
func comparePattern(r io.Reader, size int64) error {
	buf := make([]byte, 32<<10)
	var off int64
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] != patternByte(off+int64(i)) {
				return fmt.Errorf("byte %d is %d, want %d", off+int64(i), buf[i], patternByte(off+int64(i)))
			}
		}
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if off != size {
		return fmt.Errorf("the file is %d bytes, want %d", off, size)
	}
	return nil
}

// bigMultipart is a multipart body of the given size that never exists as a
// value: the envelope is two short strings and the payload is generated as it
// is read.
func bigMultipart(field, filename string, size int64) (io.Reader, string) {
	const boundary = "----pelfsStreamingBoundary"
	head := "--" + boundary + "\r\n" +
		fmt.Sprintf("Content-Disposition: form-data; name=%q; filename=%q\r\n", field, filename) +
		"Content-Type: application/octet-stream\r\n\r\n"
	tail := "\r\n--" + boundary + "--\r\n"
	return io.MultiReader(
			strings.NewReader(head),
			&patternReader{left: size},
			strings.NewReader(tail),
		),
		"multipart/form-data; boundary=" + boundary
}
