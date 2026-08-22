package fakeorigin

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestConcurrentPutsToOneKeyAreLastWriterWins pins the property every test in
// this repo that races two writers on one object depends on, and which this
// origin did not have.
//
// PUT used to stage through a fixed `<key>.upload`, shared by every request
// for that key. Two concurrent PUTs therefore opened ONE file, wrote into it
// at their own offsets, and one of them renamed it into place while the other
// was still writing — into what was now the object. The loser's rename found
// nothing and answered 500. So a writer could be told its PUT failed while
// its bytes were live, and a writer could be told it succeeded while the
// object held somebody else's.
//
// That is not a failure mode any origin has, and it cost two CI runs: it is
// what produced the `500 Internal Server Error` in the log next to
// internal/lease's TestRenewalDetectsConflict failure, and a landed PUT
// reported as failed was the input the lease's ETag bookkeeping could not
// survive.
//
// Real object storage is last-writer-wins on a whole PUT: both writers
// succeed, and the object holds exactly one of the two bodies.
func TestConcurrentPutsToOneKeyAreLastWriterWins(t *testing.T) {
	srv := httptest.NewServer(Handler(t.TempDir()))
	defer srv.Close()

	// Big enough that the two bodies cannot each land in one write, which is
	// what made the shared temp file produce a MIXTURE rather than merely a
	// wrong winner.
	bodies := [][]byte{
		bytes.Repeat([]byte("a"), 512<<10),
		bytes.Repeat([]byte("b"), 512<<10),
	}
	url := srv.URL + "/ns/meta/contended.json"

	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, len(bodies))
		for _, body := range bodies {
			wg.Add(1)
			go func(body []byte) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
				if err != nil {
					errs <- err
					return
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errs <- err
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode/100 != 2 {
					msg, _ := io.ReadAll(resp.Body)
					errs <- fmt.Errorf("PUT: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
				}
			}(body)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: a concurrent PUT failed, which no origin does: %v", round, err)
		}

		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, bodies[0]) && !bytes.Equal(got, bodies[1]) {
			t.Fatalf("round %d: the object holds neither writer's body (%d bytes, starts %q): the two "+
				"PUTs shared a staging file", round, len(got), string(got[:min(16, len(got))]))
		}
	}
}
