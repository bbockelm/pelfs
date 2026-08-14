// Package sqlite3 is a cgo-free stand-in for github.com/mattn/go-sqlite3,
// backed by modernc.org/sqlite. It is substituted for the real package via a
// go.mod replace directive so that JuiceFS's SQLite metadata engine builds
// with CGO_ENABLED=0.
//
// It provides the small API surface JuiceFS actually uses:
//   - a database/sql driver registered under the name "sqlite3"
//   - the Error / ErrNo types and the ErrBusy / ErrConstraint codes
//
// The driver translates mattn-style DSN query parameters (_journal, _timeout,
// ...) into modernc _pragma parameters, and converts modernc errors into
// mattn-shaped Error values so JuiceFS's duplicate-entry and busy-retry
// detection keeps working.
package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"strings"

	sqlite "modernc.org/sqlite"
)

// ErrNo mirrors mattn/go-sqlite3's primary result code type.
type ErrNo int

// ErrNoExtended mirrors mattn/go-sqlite3's extended result code type.
type ErrNoExtended int

const (
	ErrError      ErrNo = 1
	ErrBusy       ErrNo = 5
	ErrLocked     ErrNo = 6
	ErrConstraint ErrNo = 19
)

func (e ErrNo) Error() string {
	return fmt.Sprintf("sqlite3 error code %d", int(e))
}

func (e ErrNoExtended) Error() string {
	return fmt.Sprintf("sqlite3 extended error code %d", int(e))
}

// Error mirrors mattn/go-sqlite3's Error struct closely enough for callers
// that do `err.(sqlite3.Error)` and inspect Code.
type Error struct {
	Code         ErrNo
	ExtendedCode ErrNoExtended
	err          string
}

func (e Error) Error() string { return e.err }

// Is lets errors.Is(err, sqlite3.ErrBusy) succeed on translated errors.
func (e Error) Is(target error) bool {
	if n, ok := target.(ErrNo); ok {
		return e.Code == n
	}
	if n, ok := target.(ErrNoExtended); ok {
		return e.ExtendedCode == n
	}
	return false
}

func init() {
	sql.Register("sqlite3", &shimDriver{inner: &sqlite.Driver{}})
}

type shimDriver struct {
	inner driver.Driver
}

func (d *shimDriver) Open(dsn string) (driver.Conn, error) {
	c, err := d.inner.Open(translateDSN(dsn))
	if err != nil {
		return nil, wrapErr(err)
	}
	return &conn{inner: c}, nil
}

// translateDSN converts a mattn-style DSN (path?cache=shared&_journal=WAL)
// into a modernc-style DSN (path?_pragma=journal_mode(WAL)).
func translateDSN(dsn string) string {
	base, rawQuery, hasQuery := strings.Cut(dsn, "?")
	if !hasQuery {
		return dsn
	}
	in, err := url.ParseQuery(rawQuery)
	if err != nil {
		return base
	}
	out := url.Values{}
	addPragma := func(name, v string) {
		out.Add("_pragma", fmt.Sprintf("%s(%s)", name, v))
	}
	for k, vs := range in {
		for _, v := range vs {
			switch k {
			case "_journal", "_journal_mode":
				addPragma("journal_mode", v)
			case "_timeout", "_busy_timeout":
				addPragma("busy_timeout", v)
			case "_sync", "_synchronous":
				addPragma("synchronous", v)
			case "_fk", "_foreign_keys":
				addPragma("foreign_keys", v)
			case "_pragma", "mode", "_txlock", "_time_format":
				out.Add(k, v)
			default:
				// Drop parameters modernc does not understand
				// (e.g. cache=shared).
			}
		}
	}
	if enc := out.Encode(); enc != "" {
		return base + "?" + enc
	}
	return base
}

func wrapErr(err error) error {
	if err == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		code := se.Code()
		return Error{
			Code:         ErrNo(code & 0xff),
			ExtendedCode: ErrNoExtended(code),
			err:          se.Error(),
		}
	}
	return err
}

// conn wraps the modernc connection, translating errors on the paths JuiceFS
// exercises. Optional interfaces are forwarded when the inner connection
// implements them and skipped (letting database/sql fall back) otherwise.
type conn struct {
	inner driver.Conn
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	s, err := c.inner.Prepare(query)
	if err != nil {
		return nil, wrapErr(err)
	}
	return &stmt{inner: s}, nil
}

func (c *conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if p, ok := c.inner.(driver.ConnPrepareContext); ok {
		s, err := p.PrepareContext(ctx, query)
		if err != nil {
			return nil, wrapErr(err)
		}
		return &stmt{inner: s}, nil
	}
	return c.Prepare(query)
}

func (c *conn) Close() error { return wrapErr(c.inner.Close()) }

func (c *conn) Begin() (driver.Tx, error) {
	tx, err := c.inner.Begin() //nolint:staticcheck // fallback path only
	return tx, wrapErr(err)
}

func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.inner.(driver.ConnBeginTx); ok {
		tx, err := b.BeginTx(ctx, opts)
		return tx, wrapErr(err)
	}
	return c.Begin()
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := c.inner.(driver.ExecerContext); ok {
		r, err := e.ExecContext(ctx, query, args)
		return r, wrapErr(err)
	}
	return nil, driver.ErrSkip
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if q, ok := c.inner.(driver.QueryerContext); ok {
		r, err := q.QueryContext(ctx, query, args)
		return r, wrapErr(err)
	}
	return nil, driver.ErrSkip
}

func (c *conn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return wrapErr(p.Ping(ctx))
	}
	return nil
}

func (c *conn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *conn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

type stmt struct {
	inner driver.Stmt
}

func (s *stmt) Close() error  { return wrapErr(s.inner.Close()) }
func (s *stmt) NumInput() int { return s.inner.NumInput() }

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	r, err := s.inner.Exec(args) //nolint:staticcheck // fallback path only
	return r, wrapErr(err)
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	r, err := s.inner.Query(args) //nolint:staticcheck // fallback path only
	return r, wrapErr(err)
}

func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := s.inner.(driver.StmtExecContext); ok {
		r, err := e.ExecContext(ctx, args)
		return r, wrapErr(err)
	}
	vals, err := namedToValues(args)
	if err != nil {
		return nil, err
	}
	return s.Exec(vals)
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if q, ok := s.inner.(driver.StmtQueryContext); ok {
		r, err := q.QueryContext(ctx, args)
		return r, wrapErr(err)
	}
	vals, err := namedToValues(args)
	if err != nil {
		return nil, err
	}
	return s.Query(vals)
}

func namedToValues(args []driver.NamedValue) ([]driver.Value, error) {
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		if a.Name != "" {
			return nil, errors.New("sqlite3 shim: named parameters not supported in fallback path")
		}
		vals[i] = a.Value
	}
	return vals, nil
}
