package main

// The branch picker's server half, driven through the real verb.
//
// THE ASSERTION THAT MATTERS MOST is not that the switch happens: it is
// that NOTHING IS LEFT BEHIND ON THE OLD GENERATION. A route that moves the
// session but leaves the WebDAV handler, the JSON data plane or the
// durability panel pointed at the branch it came from would be worse than
// no route at all — the page would confidently show one branch's files
// under another branch's name. So every test here checks the surfaces, not
// just the answer.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (l *liveBrowse) branches() branchList {
	l.t.Helper()
	res := l.req("GET", "/api/v1/branches", "")
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		l.t.Fatalf("GET /api/v1/branches: %d %s", res.StatusCode, b)
	}
	var out branchList
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		l.t.Fatal(err)
	}
	return out
}

// switchTo posts the switch and returns the status and the decoded body.
func (l *liveBrowse) switchTo(name string) (int, map[string]any) {
	l.t.Helper()
	res := l.req("POST", "/api/v1/branch", `{"name":"`+name+`"}`)
	defer res.Body.Close() //nolint:errcheck
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

// awaitJob waits for the current job to finish and returns it.
func (l *liveBrowse) awaitJob(what string) *publishJob {
	l.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		st := l.state()
		if st.Publish != nil && st.Publish.State != "running" {
			return st.Publish
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("%s: the job never finished", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// listRoot is the JSON data plane's answer for "/", as the file manager
// asks it. It is the surface a stale binding would betray.
func (l *liveBrowse) listRoot() string {
	l.t.Helper()
	res := l.req("GET", "/api/v1/files", "")
	defer res.Body.Close() //nolint:errcheck
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		l.t.Fatalf("GET /api/v1/files: %d %s", res.StatusCode, b)
	}
	return string(b)
}

// davRoot is the WebDAV surface's answer for the same directory. It is a
// SEPARATE handler built over the same binding, and the point of asking it
// is that "the JSON API followed the switch" does not imply "the WebDAV
// handler did".
func (l *liveBrowse) davRoot() (int, string) {
	l.t.Helper()
	req, err := http.NewRequest("PROPFIND", l.base+"/dav/", strings.NewReader(""))
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Depth", "1")
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		l.t.Fatalf("PROPFIND /dav/: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// TestTheBranchListIsTheVolumesBranches covers the drop-down's data: the
// names, which one is current, and what has work.
func TestTheBranchListIsTheVolumesBranches(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	l.awaitReady(br)

	got := l.branches()
	if got.Current != "main" {
		t.Errorf("current = %q, want main", got.Current)
	}
	if len(got.Branches) != 1 || got.Branches[0].Name != "main" {
		t.Fatalf("branches = %+v, want just main", got.Branches)
	}
	// The row carries what the picker needs to show which is current and
	// which has work, and the head is there so "which one did I publish
	// from" needs no second request.
	if got.Branches[0].Head == "" {
		t.Error("the branch row carries no head")
	}
	if got.Branches[0].Staged {
		t.Error("a session that has written nothing reports staged work")
	}

	// Stage something, and the row says so — which is the fact the picker
	// uses to warn before a switch it would have to refuse.
	l.upload("staged.txt", "not published")
	got = l.branches()
	if !got.Branches[0].Staged {
		t.Error("staged work is not reported on the branch it is staged on")
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestSwitchingBranchesMovesEverySurface is the whole point of the route.
func TestSwitchingBranchesMovesEverySurface(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	l.awaitReady(br)

	// A file on main, published, so the two branches have different
	// contents and a stale binding is VISIBLE rather than merely possible.
	l.upload("only-on-main.txt", "main")
	res := l.req("POST", "/api/v1/publish", "{}")
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("publish: %d", res.StatusCode)
	}
	if job := l.awaitJob("the publish"); job.State != "done" {
		t.Fatalf("publish ended as %q: %s", job.State, job.Error)
	}
	if !strings.Contains(l.listRoot(), "only-on-main.txt") {
		t.Fatal("the file published onto main is not in the listing")
	}

	// A second branch, made from main's head and then made DIFFERENT: it
	// is created at main's current generation, so the two are identical
	// until something changes. Switching to it and back is still the test
	// of the surfaces, and the generation is what distinguishes them.
	if code := cmdBranch([]string{"--state-dir", l.stateDir, "--from", "main", l.prefix, "dev"}); code != 0 {
		t.Fatalf("pelfs branch exited %d", code)
	}

	list := l.branches()
	if len(list.Branches) != 2 {
		t.Fatalf("branches = %+v, want main and dev", list.Branches)
	}
	if list.Current != "main" {
		t.Errorf("current = %q", list.Current)
	}

	// THE SWITCH.
	code, body := l.switchTo("dev")
	if code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/branch: %d %v, want 202", code, body)
	}
	job := l.awaitJob("the switch")
	if job.State != "done" {
		t.Fatalf("the switch ended as %q: %s", job.State, job.Error)
	}
	if job.Reason != "branch" {
		t.Errorf("the job's reason is %q, so the page cannot tell a switch from a publish", job.Reason)
	}

	// 1. THE DURABILITY PANEL. /events and /api/v1/info are the same
	// document, and it must name the branch the session is actually on.
	st := l.state()
	if st.Branch != "dev" {
		t.Errorf("the page still says branch %q after switching to dev", st.Branch)
	}
	if st.Phase != "ready" {
		t.Errorf("phase = %q after a switch", st.Phase)
	}
	// 2. THE STREAM, which is what the page actually reads: a frame must
	// arrive carrying the new branch, on the connection that was open
	// across the switch.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if s := readSSEState(t, br); s.Branch == "dev" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no frame naming the new branch arrived on the stream")
		}
	}
	// 3. THE BRANCH LIST agrees about which one is current.
	if got := l.branches(); got.Current != "dev" {
		t.Errorf("the branch list still reports %q as current", got.Current)
	}
	// 4. THE JSON DATA PLANE serves the new generation.
	if !strings.Contains(l.listRoot(), "only-on-main.txt") {
		t.Error("dev was forked from main's head and does not carry its file")
	}
	// 5. THE WEBDAV HANDLER, separately, because it is a separate handler
	// and browseServer.serveDAV answers 503 out of a NIL one — which is
	// exactly what a switch that forgot to rebuild it would leave behind.
	// 401 is the pass: the handler exists and the request reached its
	// authenticator. Going further would mean minting an OAuth credential
	// and consenting to it, which internal/localoauth's own tests do; what
	// is asserted here is that the switch left a handler at all, and
	// setReady builds it and the JSON binding from the one filesystem, so
	// assertion 4 covers which generation they serve.
	if code, body := l.davRoot(); code == http.StatusServiceUnavailable {
		t.Errorf("PROPFIND /dav/ after the switch: 503 — the WebDAV handler was not "+
			"rebuilt, so /dav/ is dead for the rest of the session: %.200s", body)
	}

	// And back again, because a switch that only works once is a switch
	// that left something behind the first time.
	if code, body := l.switchTo("main"); code != http.StatusAccepted {
		t.Fatalf("switching back: %d %v", code, body)
	}
	if job := l.awaitJob("the switch back"); job.State != "done" {
		t.Fatalf("the switch back ended as %q: %s", job.State, job.Error)
	}
	if st := l.state(); st.Branch != "main" {
		t.Errorf("branch = %q after switching back", st.Branch)
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestSwitchingRefusesToStrandStagedWork is the 409, and the reason the
// route has one: a picker that silently discarded an overlay would lose an
// afternoon of uploads to one click.
func TestSwitchingRefusesToStrandStagedWork(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	l.awaitReady(br)
	if code := cmdBranch([]string{"--state-dir", l.stateDir, "--from", "main", l.prefix, "dev"}); code != 0 {
		t.Fatalf("pelfs branch exited %d", code)
	}

	l.upload("unpublished.txt", "this must survive a refused switch")
	code, body := l.switchTo("dev")
	if code != http.StatusConflict {
		t.Fatalf("switching with staged work: %d %v, want 409", code, body)
	}
	reason, _ := body["reason"].(string)
	if !strings.Contains(reason, "publish or discard") {
		t.Errorf("the 409 does not say what to do about it: %v", body)
	}
	// THE WORK IS STILL THERE. A refusal that lost the overlay while
	// refusing would be the bug the refusal exists to prevent.
	if st := l.state(); st.Branch != "main" || st.StagedFiles == 0 {
		t.Errorf("after a refused switch: branch %q, %d staged", st.Branch, st.StagedFiles)
	}
	if !strings.Contains(l.listRoot(), "unpublished.txt") {
		t.Error("the staged file is gone from the listing after a refused switch")
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestAReadOnlySessionSwitchesBranches records the decision the contract
// left open: a read-only session is NOT refused.
//
// It has no overlay to strand, no lease to move and nothing to publish, so
// a switch is a generation swap and nothing else — the safest form of the
// operation, in the session where reading across branches is the most
// natural thing to be doing. There is no 403 on this route.
func TestAReadOnlySessionSwitchesBranches(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: false},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	l.awaitReady(br)
	if code := cmdBranch([]string{"--state-dir", l.stateDir, "--from", "main", l.prefix, "dev"}); code != 0 {
		t.Fatalf("pelfs branch exited %d", code)
	}

	code, body := l.switchTo("dev")
	if code != http.StatusAccepted {
		t.Fatalf("a read-only session was refused the switch: %d %v", code, body)
	}
	if job := l.awaitJob("the read-only switch"); job.State != "done" {
		t.Fatalf("the switch ended as %q: %s", job.State, job.Error)
	}
	if st := l.state(); st.Branch != "dev" {
		t.Errorf("branch = %q", st.Branch)
	}
	if code, _ := l.davRoot(); code == http.StatusServiceUnavailable {
		t.Error("PROPFIND /dav/ after a read-only switch: 503, so the handler was not rebuilt")
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestSwitchingToNonsenseIsRefusedWithoutMovingAnything covers the two
// refusals that must leave the session exactly as it was.
func TestSwitchingToNonsenseIsRefusedWithoutMovingAnything(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	l.awaitReady(br)

	// A name the key space cannot carry: refused before anything is
	// fetched, as a 400 rather than a job that fails.
	if code, _ := l.switchTo("../etc"); code != http.StatusBadRequest {
		t.Errorf("a bad branch name answered %d, want 400", code)
	}
	// A name that is fine and names no branch: accepted as a job, because
	// finding out costs a round trip, and the job FAILS with the reason.
	code, _ := l.switchTo("no-such-branch")
	if code != http.StatusAccepted {
		t.Fatalf("switching to an absent branch answered %d", code)
	}
	job := l.awaitJob("the doomed switch")
	if job.State != "failed" {
		t.Errorf("switching to an absent branch ended as %q", job.State)
	}
	// And the session is still on main, still serving.
	st := l.stillServing("after a refused switch")
	if st.Branch != "main" {
		t.Errorf("branch = %q after a failed switch", st.Branch)
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}
