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
)

// Handler serves the origin namespace from root.
func Handler(root string) http.Handler {
	return &origin{root: root}
}

type origin struct {
	root string
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
		tmp := p + ".upload"
		f, err := os.Create(tmp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
