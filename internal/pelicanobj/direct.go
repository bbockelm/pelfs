package pelicanobj

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juicedata/juicefs/pkg/object"
)

// directStore talks to a single HTTP(S) server (an origin, or the fakeorigin
// test server) with no federation discovery. Test/dev transport.
type directStore struct {
	object.DefaultObjectStorage
	base *url.URL // endpoint + prefix path; object keys appended below this
	tok  *tokenSource
	hc   *http.Client
}

var _ Store = (*directStore)(nil)

func newDirectStore(ctx context.Context, cfg Config, u *url.URL) (*directStore, error) {
	base := *u
	base.Path = strings.TrimRight(base.Path, "/")
	return &directStore{
		base: &base,
		tok:  &tokenSource{path: cfg.TokenPath},
		hc:   newHTTPClient(cfg.Insecure),
	}, nil
}

func newHTTPClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 64
	if insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Go strips Authorization when the redirect changes host; a
			// redirect target within the same trust domain needs the same
			// token.
			if auth := via[0].Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
			return nil
		},
	}
}

// keyURL maps an object key to its absolute URL beneath the prefix.
func (s *directStore) keyURL(key string) string {
	u := *s.base
	u.Path = s.base.Path + "/" + strings.TrimLeft(key, "/")
	return u.String()
}

func (s *directStore) newReq(ctx context.Context, method, key string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.keyURL(key), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if tok := s.tok.get(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, nil
}

func (s *directStore) String() string {
	return fmt.Sprintf("pelican+direct://%s%s/", s.base.Host, s.base.Path)
}

func (s *directStore) Limits() object.Limits {
	return object.Limits{IsSupportMultipartUpload: false}
}

func (s *directStore) Create(ctx context.Context) error {
	// Namespaces exist a priori; nothing to create.
	return nil
}

func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

func statusErr(op, key string, resp *http.Response) error {
	err := fmt.Errorf("pelican %s %q: %s", op, key, resp.Status)
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %w", err, os.ErrNotExist)
	}
	return err
}

func (s *directStore) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	req, err := s.newReq(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	if off > 0 || limit > 0 {
		if limit > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+limit-1))
		} else {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
		}
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusPartialContent:
		return resp.Body, nil
	case http.StatusOK:
		// Server ignored the Range header; emulate it.
		if off > 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, off); err != nil {
				drainAndClose(resp)
				return nil, fmt.Errorf("pelican get %q: skip %d bytes: %w", key, off, err)
			}
		}
		if limit > 0 {
			return struct {
				io.Reader
				io.Closer
			}{io.LimitReader(resp.Body, limit), resp.Body}, nil
		}
		return resp.Body, nil
	default:
		defer drainAndClose(resp)
		return nil, statusErr("get", key, resp)
	}
}

func (s *directStore) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
	var body io.ReadSeeker
	if rs, ok := in.(io.ReadSeeker); ok {
		body = rs
	} else {
		data, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	size, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	req, err := s.newReq(ctx, http.MethodPut, key, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.GetBody = func() (io.ReadCloser, error) {
		if _, err := body.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return io.NopCloser(body), nil
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer drainAndClose(resp)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		s.tok.invalidate()
	}
	return statusErr("put", key, resp)
}

func (s *directStore) Delete(ctx context.Context, key string, getters ...object.AttrGetter) error {
	req, err := s.newReq(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer drainAndClose(resp)
	if resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}
	return statusErr("delete", key, resp)
}

func (s *directStore) Head(ctx context.Context, key string) (object.Object, error) {
	ki, err := s.StatKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return newObj(key, ki.Size, ki.Mtime, strings.HasSuffix(key, "/")), nil
}

func (s *directStore) StatKey(ctx context.Context, key string) (*KeyInfo, error) {
	req, err := s.newReq(ctx, http.MethodHead, key, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("head", key, resp)
	}
	size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	mtime, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return &KeyInfo{Size: size, Mtime: mtime, ETag: resp.Header.Get("ETag")}, nil
}

// ListDir lists the immediate children of dir via WebDAV PROPFIND.
func (s *directStore) ListDir(ctx context.Context, dir string) ([]DirEntry, error) {
	req, err := s.newReq(ctx, "PROPFIND", strings.Trim(dir, "/"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", "1")
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		drainAndClose(resp)
		return nil, statusErr("propfind", dir, resp)
	}
	entries, err := parseMultistatus(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pelican propfind %q: %w", dir, err)
	}
	// The collection itself is included in the multistatus response; filter
	// it out by comparing against the request path.
	selfPath := strings.TrimRight(joinURLPath(s.base.Path, strings.Trim(dir, "/")), "/")
	res := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		if strings.TrimRight(e.href, "/") == selfPath {
			continue
		}
		res = append(res, DirEntry{Name: path.Base(e.href), IsDir: e.isDir, Size: e.size, Mtime: e.mtime})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

func (s *directStore) ListAll(ctx context.Context, prefix, marker string, followLink bool) (<-chan object.Object, error) {
	return listAll(ctx, s, prefix, marker)
}

func joinURLPath(a, b string) string {
	if b == "" {
		return a
	}
	return strings.TrimRight(a, "/") + "/" + b
}

type davEntry struct {
	href  string
	isDir bool
	size  int64
	mtime time.Time
}

type multistatus struct {
	XMLName   xml.Name      `xml:"multistatus"`
	Responses []davResponse `xml:"response"`
}

type davResponse struct {
	Href     string        `xml:"href"`
	Propstat []davPropstat `xml:"propstat"`
}

type davPropstat struct {
	Status string  `xml:"status"`
	Prop   davProp `xml:"prop"`
}

type davProp struct {
	Length       string      `xml:"getcontentlength"`
	LastModified string      `xml:"getlastmodified"`
	ResourceType davResGroup `xml:"resourcetype"`
}

type davResGroup struct {
	Collection *struct{} `xml:"collection"`
}

func parseMultistatus(r io.Reader) ([]davEntry, error) {
	var ms multistatus
	if err := xml.NewDecoder(io.LimitReader(r, 64<<20)).Decode(&ms); err != nil {
		return nil, err
	}
	entries := make([]davEntry, 0, len(ms.Responses))
	for _, resp := range ms.Responses {
		href, err := url.PathUnescape(strings.TrimSpace(resp.Href))
		if err != nil {
			href = strings.TrimSpace(resp.Href)
		}
		if u, err := url.Parse(href); err == nil && u.Path != "" {
			href = u.Path
		}
		e := davEntry{href: href}
		for _, ps := range resp.Propstat {
			if ps.Status != "" && !strings.Contains(ps.Status, "200") {
				continue
			}
			if ps.Prop.ResourceType.Collection != nil || strings.HasSuffix(href, "/") {
				e.isDir = true
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(ps.Prop.Length), 10, 64); err == nil {
				e.size = n
			}
			if t, err := http.ParseTime(strings.TrimSpace(ps.Prop.LastModified)); err == nil {
				e.mtime = t
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// tokenSource resolves and caches a bearer token, re-reading its backing
// file when it changes and honoring WLCG bearer-token discovery.
type tokenSource struct {
	path string

	mu       sync.Mutex
	cached   string
	loadedAt time.Time
}

func (t *tokenSource) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.loadedAt) < 30*time.Second {
		return t.cached
	}
	t.cached = t.load()
	t.loadedAt = time.Now()
	return t.cached
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.loadedAt = time.Time{}
	t.mu.Unlock()
}

func (t *tokenSource) load() string {
	if t.path != "" {
		return readTokenFile(t.path)
	}
	if tok := strings.TrimSpace(os.Getenv("BEARER_TOKEN")); tok != "" {
		return tok
	}
	if p := os.Getenv("BEARER_TOKEN_FILE"); p != "" {
		return readTokenFile(p)
	}
	btName := fmt.Sprintf("bt_u%d", os.Getuid())
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if tok := readTokenFile(dir + "/" + btName); tok != "" {
			return tok
		}
	}
	return readTokenFile("/tmp/" + btName)
}

func readTokenFile(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
