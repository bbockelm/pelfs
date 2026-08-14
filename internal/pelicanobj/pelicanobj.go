// Package pelicanobj implements a JuiceFS object-storage backend that stores
// objects in a Pelican federation beneath a fixed namespace prefix.
//
// Objects are addressed as <endpoint>/<prefix>/<key> where <endpoint> is the
// federation's director (discovered from the pelican:// URL via the
// .well-known/pelican-configuration metadata) or, for https:// URLs, the
// given server itself. All transfers are plain HTTP GET/PUT/DELETE/HEAD plus
// WebDAV PROPFIND for listings, authenticated with a bearer token.
package pelicanobj

import (
	"bytes"
	"context"
	"encoding/json"
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

const userAgent = "pelfs/0.1"

// Config controls construction of a Store.
type Config struct {
	// PrefixURL is the root under which all objects are stored, either
	// pelican://<federation>/<path> or https://<server>/<path>.
	PrefixURL string
	// TokenPath is an explicit bearer-token file. When empty, standard
	// WLCG bearer-token discovery is used ($BEARER_TOKEN,
	// $BEARER_TOKEN_FILE, $XDG_RUNTIME_DIR/bt_u$UID, /tmp/bt_u$UID).
	TokenPath string
	// Insecure skips TLS verification (for local test federations).
	Insecure bool
}

// Store implements object.ObjectStorage on a Pelican federation.
type Store struct {
	object.DefaultObjectStorage
	base *url.URL // endpoint + prefix path; object keys appended below this
	tok  *tokenSource
	hc   *http.Client
}

var _ object.ObjectStorage = (*Store)(nil)

// New builds a Store for the given prefix URL, performing federation
// discovery for pelican:// URLs.
func New(ctx context.Context, cfg Config) (*Store, error) {
	u, err := url.Parse(cfg.PrefixURL)
	if err != nil {
		return nil, fmt.Errorf("parse prefix URL: %w", err)
	}
	tok := &tokenSource{path: cfg.TokenPath}
	hc := newHTTPClient(cfg.Insecure)

	var base *url.URL
	switch u.Scheme {
	case "pelican", "osdf":
		fed := u.Host
		if u.Scheme == "osdf" && fed == "" {
			fed = "osg-htc.org"
		}
		endpoint, err := discoverDirector(ctx, hc, fed)
		if err != nil {
			return nil, err
		}
		base, err = url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse director endpoint %q: %w", endpoint, err)
		}
		base.Path = path.Join(base.Path, u.Path)
	case "https", "http":
		base = u
	default:
		return nil, fmt.Errorf("unsupported prefix URL scheme %q (want pelican:// or https://)", u.Scheme)
	}
	base.Path = strings.TrimRight(base.Path, "/")
	return &Store{base: base, tok: tok, hc: hc}, nil
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
			// Go strips Authorization when the redirect changes host;
			// within a federation the redirect target (cache/origin) needs
			// the same token the director saw.
			if auth := via[0].Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
			return nil
		},
	}
}

type federationConfig struct {
	DirectorEndpoint string `json:"director_endpoint"`
}

func discoverDirector(ctx context.Context, hc *http.Client, federation string) (string, error) {
	u := "https://" + federation + "/.well-known/pelican-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("federation discovery %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("federation discovery %s: unexpected status %s", u, resp.Status)
	}
	var fc federationConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&fc); err != nil {
		return "", fmt.Errorf("federation discovery %s: parse: %w", u, err)
	}
	if fc.DirectorEndpoint == "" {
		return "", fmt.Errorf("federation discovery %s: no director_endpoint", u)
	}
	return fc.DirectorEndpoint, nil
}

// keyURL maps an object key to its absolute URL beneath the prefix.
func (s *Store) keyURL(key string) string {
	u := *s.base
	u.Path = s.base.Path + "/" + strings.TrimLeft(key, "/")
	return u.String()
}

func (s *Store) newReq(ctx context.Context, method, key string, body io.Reader) (*http.Request, error) {
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

func (s *Store) String() string {
	return fmt.Sprintf("pelican://%s%s/", s.base.Host, s.base.Path)
}

func (s *Store) Limits() object.Limits {
	return object.Limits{IsSupportMultipartUpload: false}
}

func (s *Store) Create(ctx context.Context) error {
	// Namespaces exist a priori in the federation; nothing to create.
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

func (s *Store) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
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

func (s *Store) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
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

func (s *Store) Delete(ctx context.Context, key string, getters ...object.AttrGetter) error {
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

func (s *Store) Head(ctx context.Context, key string) (object.Object, error) {
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
	return newObj(key, size, mtime, strings.HasSuffix(key, "/")), nil
}

// DirEntry describes one entry from ListDir.
type DirEntry struct {
	Name  string // base name, no slashes; directories end without markers
	IsDir bool
	Size  int64
	Mtime time.Time
}

// ListDir lists the immediate children of dir (a key-space directory path
// relative to the prefix, "" for the prefix root) via WebDAV PROPFIND.
func (s *Store) ListDir(ctx context.Context, dir string) ([]DirEntry, error) {
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
	out := entries[:0]
	for _, e := range entries {
		if strings.TrimRight(e.href, "/") == selfPath {
			continue
		}
		out = append(out, e)
	}
	res := make([]DirEntry, 0, len(out))
	for _, e := range out {
		res = append(res, DirEntry{Name: path.Base(e.href), IsDir: e.isDir, Size: e.size, Mtime: e.mtime})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

func joinURLPath(a, b string) string {
	if b == "" {
		return a
	}
	return strings.TrimRight(a, "/") + "/" + b
}

// ListAll walks the prefix depth-first in sorted order, emitting every
// object whose key begins with prefix and sorts after marker. Used by
// snapshot restore and by JuiceFS offline tools (gc/fsck), not by the mount
// data path.
func (s *Store) ListAll(ctx context.Context, prefix, marker string, followLink bool) (<-chan object.Object, error) {
	ch := make(chan object.Object, 64)
	go func() {
		defer close(ch)
		s.walk(ctx, "", prefix, marker, ch)
	}()
	return ch, nil
}

func (s *Store) walk(ctx context.Context, dir, prefix, marker string, ch chan<- object.Object) {
	entries, err := s.ListDir(ctx, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		key := e.Name
		if dir != "" {
			key = dir + "/" + e.Name
		}
		if e.IsDir {
			// Skip subtrees that cannot contain matching keys.
			dirPrefix := key + "/"
			if prefix != "" && !strings.HasPrefix(dirPrefix, prefix) && !strings.HasPrefix(prefix, dirPrefix) {
				continue
			}
			s.walk(ctx, key, prefix, marker, ch)
			continue
		}
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		if marker != "" && key <= marker {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case ch <- newObj(key, e.Size, e.Mtime, false):
		}
	}
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

type pobj struct {
	key   string
	size  int64
	mtime time.Time
	isDir bool
}

func newObj(key string, size int64, mtime time.Time, isDir bool) object.Object {
	return &pobj{key: key, size: size, mtime: mtime, isDir: isDir}
}

func (o *pobj) Key() string          { return o.key }
func (o *pobj) Size() int64          { return o.size }
func (o *pobj) Mtime() time.Time     { return o.mtime }
func (o *pobj) IsDir() bool          { return o.isDir }
func (o *pobj) IsSymlink() bool      { return false }
func (o *pobj) StorageClass() string { return "" }
func (o *pobj) Status() string       { return "" }

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
