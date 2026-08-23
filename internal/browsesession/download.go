package browsesession

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// TicketPathValue is the wildcard name the download route must use:
// mount DownloadHandler at "GET /d/{ticket}" so PathValue finds it.
const TicketPathValue = "ticket"

// Source is where a ticketed download gets its bytes. It is the seam U11
// fills in: M1 has no file surface, so `pelfs browse` registers no source
// and every redemption 404s — but the route, the ticket lifecycle and the
// no-credential property are in place and tested, because they are the
// part that is easy to get wrong later and impossible to retrofit.
//
// An implementation must apply the SAME permission model the rest of the
// filesystem does (internal/fsperm, through internal/vfsbilly) and must
// return ErrForbidden rather than the bytes when the session's mode does
// not permit the read. It must not consult the request: by the time it is
// called, the only statement about what to serve is the ticket's path.
type Source interface {
	Open(ctx context.Context, p string) (*Content, error)
}

// Content is one file's bytes and the little metadata a download needs.
type Content struct {
	// Name is what the browser should save it as. It is sanitized to its
	// base name before it reaches a header.
	Name string
	// Size is used for Content-Length and for range handling; 0 with a
	// non-seekable body is acceptable.
	Size    int64
	ModTime time.Time
	// Body is the bytes. It is closed by the handler. A ReadSeeker gets
	// Range support for free through http.ServeContent; a plain Reader is
	// streamed whole.
	Body io.ReadCloser
}

// ErrForbidden is a Source's refusal on permission grounds: the path
// exists but this session may not read it. It becomes a 403, and it is
// distinct from a missing path (404) because "you cannot" and "there is
// nothing" are different answers and the user acts differently on each.
var ErrForbidden = errors.New("download refused: the session may not read this path")

// DownloadHandler serves GET /d/{ticket}: redeem, then stream.
//
// THIS ROUTE ACCEPTS NO SESSION CREDENTIAL. That is not an oversight to be
// tidied up later; it is the design. An <a href> cannot carry a custom
// request header, so a download authorized by the session token would have
// to be authorized by an ambient credential on a GET — and an
// ambient-credential GET is precisely what a cross-origin <img>, <script>,
// <iframe> or top-level navigation can trigger, and what DNS rebinding
// turned into arbitrary RPC in CVE-2018-5702. The ticket carries the
// authority instead: 256 bits, one use, 30 seconds.
//
// Three headers are not optional, and the reason is the stored-XSS problem
// (docs/design-webui.md A5). The volume holds files the user did not
// write; serving one as text/html from this origin would run its script
// with the app's own session in reach.
//
//   - Content-Type: application/octet-stream, never sniffed and never
//     derived from the extension;
//   - X-Content-Type-Options: nosniff;
//   - Content-Disposition: attachment, with no inline mode and no query
//     parameter that switches it.
//
// Losing "the browser opens the PDF for me" is a real cost and it is the
// right trade. If inline preview is ever wanted, the answer is a second
// listener on a second random port — a different origin, which cannot
// touch this one's session token — not a Content-Type switch here.
func DownloadHandler(m *Manager, src Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk, err := m.RedeemTicket(r.PathValue(TicketPathValue))
		if err != nil {
			// 404, not 401 or 403: a spent, expired or invented ticket
			// are one answer, and it says nothing about which.
			http.NotFound(w, r)
			return
		}
		if src == nil {
			// M1: the ticket mechanism exists, the file surface does not.
			http.NotFound(w, r)
			return
		}
		c, err := src.Open(r.Context(), tk.Path)
		switch {
		case errors.Is(err, ErrForbidden):
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case errors.Is(err, fs.ErrNotExist):
			http.NotFound(w, r)
			return
		case err != nil:
			http.Error(w, "cannot read that path", http.StatusInternalServerError)
			return
		}
		defer c.Body.Close() //nolint:errcheck
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", "attachment; filename="+quoteFilename(c.Name))
		if rs, ok := c.Body.(io.ReadSeeker); ok {
			// ServeContent handles Range, If-Modified-Since and the
			// Content-Length itself. It also sniffs a Content-Type when
			// the header is unset — the header is set above precisely so
			// it does not.
			http.ServeContent(w, r, "", c.ModTime, rs)
			return
		}
		if c.Size > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(c.Size, 10))
		}
		_, _ = io.Copy(w, c.Body)
	})
}

// quoteFilename renders a filename for Content-Disposition. It takes the
// base name only, and it drops anything that could end the quoted string
// or break the header — a volume path is user-controlled data, and a
// header injection here would be a genuine hole rather than a cosmetic
// bug.
func quoteFilename(name string) string {
	base := path.Base(strings.ReplaceAll(name, `\`, "/"))
	if base == "." || base == "/" || base == "" {
		base = "download"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range base {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
