package vfsdav

import (
	"encoding/xml"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/webdav"
)

// DEAD PROPERTIES, AND WHY THEY ARE IN MEMORY.
//
// A "dead" property is one the server stores verbatim for the client: x/net
// handles the ten live DAV: properties itself and passes everything else to
// a File that implements webdav.DeadPropsHolder. Without such a File every
// PROPPATCH is answered 403 and litmus's `props` suite drops below the
// ceiling this adapter has to hold — so the store exists first of all
// because the protocol says PROPPATCH works.
//
// It is memory and not the volume's xattrs, deliberately, for now:
//
//   - a client's scratch properties (Cyberduck's, Finder's, litmus's) are
//     worth exactly as long as the connection, and writing each one into the
//     overlay would put them in a published generation forever;
//   - the properties that SHOULD be durable are not dead properties at all.
//     Win32LastModifiedTime and the Win32FileAttributes read-only bit are
//     translations onto vfsbilly.Chtimes and .Chmod, which is
//     docs/design-windows.md's own work item and is not this one.
//
// The consequence is stated in the package comment and must not be
// discovered by a user: a property set over WebDAV is gone when the process
// exits. Keys are paths, so the store follows a rename and is dropped on a
// delete — an entry left behind under an old name would reappear on a file
// that happened to be created there later, which is the one way an
// in-memory store can lie about the volume rather than merely forget.
type propStore struct {
	mu sync.Mutex
	m  map[string]map[xml.Name]webdav.Property
}

func newPropStore() *propStore {
	return &propStore{m: map[string]map[xml.Name]webdav.Property{}}
}

// get returns a copy, as DeadPropsHolder requires.
func (s *propStore) get(name string) map[xml.Name]webdav.Property {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.m[name]
	if len(held) == 0 {
		return nil
	}
	out := make(map[xml.Name]webdav.Property, len(held))
	for k, v := range held {
		out[k] = v
	}
	return out
}

// patch applies one PROPPATCH atomically — all of it or none, which is what
// webdav.DeadPropsHolder specifies. A read-only binding refuses the whole
// patch with 403 rather than accepting a change to a volume that cannot
// change: the properties would be real to this process and invisible to
// every other reader of the same generation.
func (s *propStore) patch(name string, patches []webdav.Proppatch, writable bool) ([]webdav.Propstat, error) {
	if !writable {
		pstat := webdav.Propstat{Status: http.StatusForbidden}
		for _, p := range patches {
			for _, prop := range p.Props {
				pstat.Props = append(pstat.Props, webdav.Property{XMLName: prop.XMLName})
			}
		}
		return []webdav.Propstat{pstat}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	pstat := webdav.Propstat{Status: http.StatusOK}
	for _, patch := range patches {
		for _, prop := range patch.Props {
			pstat.Props = append(pstat.Props, webdav.Property{XMLName: prop.XMLName})
			if patch.Remove {
				if held := s.m[name]; held != nil {
					delete(held, prop.XMLName)
					if len(held) == 0 {
						delete(s.m, name)
					}
				}
				continue
			}
			if s.m[name] == nil {
				s.m[name] = map[xml.Name]webdav.Property{}
			}
			s.m[name][prop.XMLName] = prop
		}
	}
	return []webdav.Propstat{pstat}, nil
}

// rename moves a name and everything under it, because a MOVE of a
// collection moves the whole subtree in one call.
func (s *propStore) rename(from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if k == from {
			delete(s.m, k)
			s.m[to] = v
			continue
		}
		if strings.HasPrefix(k, from+"/") {
			delete(s.m, k)
			s.m[to+strings.TrimPrefix(k, from)] = v
		}
	}
}

// forgetTree drops a name and its subtree, which is what a DELETE means.
func (s *propStore) forgetTree(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.m {
		if k == name || strings.HasPrefix(k, name+"/") {
			delete(s.m, k)
		}
	}
}
