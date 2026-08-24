// Package fakeorigin is a minimal stand-in for a Pelican origin: an HTTP
// server speaking the subset of HTTP/WebDAV that pelfs uses (GET with Range,
// PUT with implicit parent-directory creation, DELETE, HEAD, and PROPFIND
// Depth: 1). It backs onto a local directory and is used by unit tests and
// the Docker end-to-end test.
package fakeorigin

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Handler serves the origin namespace from root.
func Handler(root string) http.Handler {
	return &origin{root: root}
}

// HandlerWithDelay serves the same namespace with a fixed delay in front
// of every request, standing in for a round trip.
//
// It exists for one measurement and says so: without a latency term, a
// loopback origin answers before a second request can be issued, so any
// concurrency table taken against it measures the hashing rate and
// nothing else. A graft's cost against a real federation is
// latency-dominated, and the number of workers that saturates it is a
// function of the RTT. Test tool only.
func HandlerWithDelay(root string, d time.Duration) http.Handler {
	return &origin{root: root, delay: d}
}

type origin struct {
	root  string
	delay time.Duration
}

// etagFor derives a strong ETag from a file's size and mtime, mimicking the
// modern origin behavior pelfs's snapshot conflict detection relies on.
func etagFor(fi os.FileInfo) string {
	return fmt.Sprintf("\"%x-%x\"", fi.Size(), fi.ModTime().UnixNano())
}

// fsPath maps a URL path to a filesystem path, rejecting escapes.
func (o *origin) fsPath(urlPath string) (string, bool) {
	clean := path.Clean("/" + urlPath)
	if strings.Contains(clean, "..") {
		return "", false
	}
	return filepath.Join(o.root, filepath.FromSlash(clean)), true
}

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o.delay > 0 {
		time.Sleep(o.delay)
	}
	p, ok := o.fsPath(r.URL.Path)
	if !ok {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", etagFor(fi))
		http.ServeFile(w, r, p) // handles Range, HEAD, Last-Modified, If-Match
	case http.MethodPut:
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// A PRIVATE staging name PER REQUEST, and this is not a detail.
		//
		// It used to be the fixed `p + ".upload"`, shared by every PUT of the
		// same key, which made two concurrent PUTs corrupt each other in ways
		// no origin does: both os.Create the same path, so they write into one
		// inode at their own offsets; whichever renames first takes that inode
		// (the other request is still writing into it, now visible AS THE
		// OBJECT), and the loser's rename finds nothing and answers 500.
		//
		// Every test that races two writers on one key — which is how this
		// repo tests detection, since there is no compare-and-swap to test
		// instead — was therefore exposed to a spurious 500 and to an object
		// holding a body its writer was told had failed. That is what made
		// TestRenewalDetectsConflict fail on two platforms in a row: the 500 it
		// produced was the trigger the lease's ETag bookkeeping could not
		// survive. Real concurrent PUTs are last-writer-wins, and now so are
		// these.
		//
		// The suffix is ".tmp" because every listing in pelfs that sweeps a
		// key space skips that suffix (refs.ValidateName documents the rule),
		// so an upload in flight cannot show up as a stray object in a
		// PROPFIND — as ".upload" could.
		f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmp := f.Name()
		if _, err := f.ReadFrom(r.Body); err != nil {
			f.Close()
			os.Remove(tmp)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := f.Close(); err != nil {
			os.Remove(tmp)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmp, p); err != nil {
			os.Remove(tmp)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if fi, err := os.Stat(p); err == nil {
			w.Header().Set("ETag", etagFor(fi))
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if err := os.Remove(p); err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		o.propfind(w, r, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type xmlResponse struct {
	Href     string `xml:"D:href"`
	Length   int64  `xml:"D:propstat>D:prop>D:getcontentlength,omitempty"`
	Modified string `xml:"D:propstat>D:prop>D:getlastmodified"`
	IsColl   *coll  `xml:"D:propstat>D:prop>D:resourcetype>D:collection,omitempty"`
	Status   string `xml:"D:propstat>D:status"`
}

type coll struct{}

type xmlMultistatus struct {
	XMLName   xml.Name      `xml:"D:multistatus"`
	NS        string        `xml:"xmlns:D,attr"`
	Responses []xmlResponse `xml:"D:response"`
}

func (o *origin) propfind(w http.ResponseWriter, r *http.Request, p string) {
	fi, err := os.Stat(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	base := strings.TrimRight(path.Clean("/"+r.URL.Path), "/")
	if base == "" {
		base = "/"
	}
	ms := xmlMultistatus{NS: "DAV:"}
	add := func(href string, fi os.FileInfo) {
		resp := xmlResponse{
			Href:     href,
			Modified: fi.ModTime().UTC().Format(http.TimeFormat),
			Status:   "HTTP/1.1 200 OK",
		}
		if fi.IsDir() {
			resp.IsColl = &coll{}
			resp.Href += "/"
		} else {
			resp.Length = fi.Size()
		}
		ms.Responses = append(ms.Responses, resp)
	}
	add(base, fi)
	if fi.IsDir() && r.Header.Get("Depth") != "0" {
		entries, err := os.ReadDir(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			cfi, err := e.Info()
			if err != nil {
				continue
			}
			href := base
			if href == "/" {
				href = ""
			}
			add(href+"/"+e.Name(), cfi)
		}
	}
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(ms)
}
