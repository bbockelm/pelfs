package main

// The SSO card (U13): the registry, the two ordering cases the design
// names, and the one thing the card must never carry.
//
// The clock is injected here for the same reason it is in idleseal_test.go:
// the TTL is ten minutes and nobody is going to wait for it.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestRegistry(notify func()) (*promptRegistry, *testClock) {
	clk := newTestClock()
	return newPromptRegistry(clk.now, notify), clk
}

// TestPromptRegistryKeepsWhatTheUserMustDo is the base case, and it also
// pins the two RFC 8628 shapes the hook normalizes: a
// verification_uri_complete arrives with an empty code, a plain
// verification_uri arrives with one.
func TestPromptRegistryKeepsWhatTheUserMustDo(t *testing.T) {
	r, _ := newTestRegistry(nil)
	r.Add("https://cilogon.org/device/?user_code=WDJB-MJHT", "")
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	cards := r.Cards()
	if len(cards) != 2 {
		t.Fatalf("%d cards, want 2", len(cards))
	}
	if cards[0].Code != "" || !strings.Contains(cards[0].URL, "user_code=") {
		t.Errorf("the complete-URL shape came out as %+v", cards[0])
	}
	if cards[1].Code != "WDJB-MJHT" {
		t.Errorf("the code-to-type shape came out as %+v", cards[1])
	}
	// Arrival order, and it is stable: a person is typing a code off this
	// list and a list that reorders under them is hostile.
	if !strings.Contains(cards[0].URL, "cilogon") {
		t.Errorf("cards are not in arrival order: %+v", cards)
	}
	if cards[0].ID == cards[1].ID || cards[0].ID == "" {
		t.Errorf("card ids collide or are empty: %q %q", cards[0].ID, cards[1].ID)
	}
}

// TestACardNeverCarriesACredential. The card is serialized straight into
// the document /events pushes to the browser, so the assertion is on the
// JSON rather than on the struct: what the page receives is the whole
// question.
func TestACardNeverCarriesACredential(t *testing.T) {
	r, _ := newTestRegistry(nil)
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	doc, err := json.Marshal(r.Cards())
	if err != nil {
		t.Fatal(err)
	}
	var generic []map[string]any
	if err := json.Unmarshal(doc, &generic); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"id": true, "url": true, "code": true, "at": true, "age_s": true, "expired": true}
	for k := range generic[0] {
		if !allowed[k] {
			t.Errorf("the card carries an unexpected field %q: %s", k, doc)
		}
	}
	// Belt and braces against a future field with an innocent name: the
	// hook is never handed a token, so no spelling of one may appear.
	for _, bad := range []string{"token", "access", "bearer", "secret", "refresh", "credential"} {
		if strings.Contains(strings.ToLower(string(doc)), bad) {
			t.Errorf("the card document mentions %q: %s", bad, doc)
		}
	}
}

// TestConcurrentPromptsAreASetNotASlot. The hook is PROCESS-WIDE — one
// atomic.Pointer, one handler — and client.AcquireToken has no
// serialization around the device flow, so two goroutines needing tokens
// for two namespaces can each open one and both land here at once.
func TestConcurrentPromptsAreASetNotASlot(t *testing.T) {
	r, _ := newTestRegistry(nil)
	var wg sync.WaitGroup
	// Ten goroutines, five distinct prompts, each raised twice: the
	// distinct ones must all survive and the repeats must fold.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Add("https://login.example.edu/device", string(rune('A'+i%5)))
		}(i)
	}
	wg.Wait()
	cards := r.Cards()
	if len(cards) != 5 {
		t.Fatalf("%d cards from 10 concurrent flows over 5 distinct prompts; want 5", len(cards))
	}
	seen := map[string]bool{}
	for _, c := range cards {
		if seen[c.ID] {
			t.Fatalf("duplicate card %q", c.ID)
		}
		seen[c.ID] = true
	}
}

// TestTheRegistryIsBounded. The hook is called by code this repo does not
// control, on goroutines it does not count. The one thing it must not be is
// unbounded.
func TestTheRegistryIsBounded(t *testing.T) {
	r, clk := newTestRegistry(nil)
	for i := 0; i < ssoPromptMax*3; i++ {
		r.Add("https://login.example.edu/device", string(rune('a'+i)))
		clk.advance(time.Second)
	}
	cards := r.Cards()
	if len(cards) != ssoPromptMax {
		t.Fatalf("%d cards after %d prompts; want the cap of %d",
			len(cards), ssoPromptMax*3, ssoPromptMax)
	}
	// Oldest first out: what it drops is what the user has newer prompts
	// on top of.
	if cards[len(cards)-1].Code != string(rune('a'+ssoPromptMax*3-1)) {
		t.Errorf("the newest prompt is not the last card: %+v", cards)
	}
}

// TestACardGreysOutRatherThanVanishing. The TTL is ours to pick because the
// issuer's expires_in is not exposed to the handler; what the design asks
// for is that the card goes grey rather than disappearing out from under
// somebody mid-typing.
func TestACardGreysOutRatherThanVanishing(t *testing.T) {
	r, clk := newTestRegistry(nil)
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	clk.advance(ssoPromptTTL - time.Second)
	if c := r.Cards(); len(c) != 1 || c[0].Expired {
		t.Fatalf("expired a second early: %+v", c)
	}
	clk.advance(2 * time.Second)
	c := r.Cards()
	if len(c) != 1 || !c[0].Expired {
		t.Fatalf("still live past the TTL, or gone entirely: %+v", c)
	}
	if c[0].AgeS < int64(ssoPromptTTL.Seconds()) {
		t.Errorf("age_s = %d, want at least the TTL", c[0].AgeS)
	}
	// And it is eventually forgotten, so a long session does not carry a
	// month of dead cards.
	clk.advance(ssoPromptGrace)
	if c := r.Cards(); len(c) != 0 {
		t.Fatalf("a card outlived the TTL plus the grace window: %+v", c)
	}
}

// TestARepeatedPromptRefreshesRatherThanDuplicating: a retried flow that
// produces the same URL and code is the same thing to do, with a fresh
// clock.
func TestARepeatedPromptRefreshesRatherThanDuplicating(t *testing.T) {
	r, clk := newTestRegistry(nil)
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	clk.advance(ssoPromptTTL - time.Minute)
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	cards := r.Cards()
	if len(cards) != 1 {
		t.Fatalf("%d cards for one repeated prompt", len(cards))
	}
	if cards[0].AgeS != 0 {
		t.Errorf("the repeat did not refresh the clock: age_s = %d", cards[0].AgeS)
	}
}

// TestTheHandlerDoesNotBlockOnTheFanOut. The hook runs on the goroutine
// driving the device flow and BLOCKS it: "a handler that blocks delays the
// user's own approval". So Add must return before anything reads the
// notification it raised.
func TestTheHandlerDoesNotBlockOnTheFanOut(t *testing.T) {
	// An unbuffered channel nobody is reading yet. If Add fanned out on the
	// caller's goroutine, this test would deadlock rather than fail — which
	// is why it is written with a timeout-free structure: Add returns, and
	// only then is the channel read.
	fan := make(chan struct{})
	r, _ := newTestRegistry(func() { fan <- struct{}{} })
	r.Add("https://login.example.edu/device", "WDJB-MJHT")
	// Reached only because Add did not wait for the send above.
	<-fan
	if c := r.Cards(); len(c) != 1 {
		t.Fatalf("%d cards after a prompt", len(c))
	}
}

// TestAPromptThatIsNotAnApprovalURLIsRefused. The URL comes from an
// issuer's device-flow response and becomes an href on the page. A CSP does
// not stop a javascript: URL a user clicks, so the refusal is here.
func TestAPromptThatIsNotAnApprovalURLIsRefused(t *testing.T) {
	r, _ := newTestRegistry(nil)
	for _, bad := range []string{
		"", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
		"/device", "https://", "file:///etc/passwd",
	} {
		r.Add(bad, "CODE")
	}
	if c := r.Cards(); len(c) != 0 {
		t.Fatalf("a non-approval URL became a card: %+v", c)
	}
	r.Add("http://127.0.0.1:8443/device", "CODE")
	if c := r.Cards(); len(c) != 1 {
		t.Fatalf("a plain http issuer was refused; test federations use them: %+v", c)
	}
}

// TestDismissIsAUserAction. The hook is one-way — nothing tells this
// process that a flow finished, failed or expired — so a card can only be
// taken off the screen by the person who dealt with it.
func TestDismissIsAUserAction(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	f.bs.prompts.Add("https://login.example.edu/device", "WDJB-MJHT")
	cards := f.bs.prompts.Cards()
	if len(cards) != 1 {
		t.Fatalf("%d cards", len(cards))
	}
	res := f.do("POST", "/api/v1/sso/dismiss", `{"id":"`+cards[0].ID+`"}`, f.tok)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		t.Fatalf("dismiss: %d", res.StatusCode)
	}
	var out map[string]bool
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out["dismissed"] {
		t.Error("the route reported nothing dismissed")
	}
	if c := f.bs.prompts.Cards(); len(c) != 0 {
		t.Fatalf("the card survived its dismissal: %+v", c)
	}
	// And the route is on the API surface, so it needs the session
	// credential like every other mutating call.
	res2 := f.do("POST", "/api/v1/sso/dismiss", `{"id":"whatever"}`, "")
	res2.Body.Close() //nolint:errcheck
	if res2.StatusCode != 401 {
		t.Errorf("dismiss without a session: %d, want 401", res2.StatusCode)
	}
}

// TestAPromptRaisedBEFOREAnyBrowserConnectedIsNotLost is the ordering
// failure docs/design-webui.md names, and it is the obvious one: a user
// runs `pelfs browse`, the browser opens, the device flow has ALREADY
// fired from primeCredential, and the page shows nothing.
//
// Two things prevent it and this test covers the second. The first is
// runBrowse's ordering — bind, serve, install the hook, THEN open the
// volume — which is asserted by TestBrowseStateBeforeAndAfterTheVolumeOpens
// and by the verb's end-to-end test. The second is that the prompt is
// STATE rather than an event: /events carries snapshots, so the first frame
// a stream ever receives already contains it, and so does /api/v1/info.
func TestAPromptRaisedBEFOREAnyBrowserConnectedIsNotLost(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	// The volume is not open yet — phase "connecting" — which is exactly
	// where primeCredential fires the flow.
	if st := f.state(); st.Phase != "connecting" {
		t.Fatalf("fixture phase = %q", st.Phase)
	}
	if n, _, _ := f.bs.idleSignal(); n != 0 {
		t.Fatalf("%d streams before the browser connected", n)
	}
	f.bs.prompts.Add("https://cilogon.org/device/?user_code=WDJB-MJHT", "")

	// Now the browser arrives. Its FIRST frame must carry the prompt.
	req, err := http.NewRequest("GET", f.srv.URL+"/events?s="+f.tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	first := readSSEState(t, bufio.NewReader(res.Body))
	if len(first.Prompts) != 1 {
		t.Fatalf("the first frame a stream ever received carries %d prompts; want the one "+
			"raised before it connected", len(first.Prompts))
	}
	if !strings.Contains(first.Prompts[0].URL, "cilogon") {
		t.Errorf("wrong prompt on the first frame: %+v", first.Prompts[0])
	}
	// The same is true of the polling half of the contract.
	if st := f.state(); len(st.Prompts) != 1 {
		t.Errorf("GET /api/v1/info carries %d prompts", len(st.Prompts))
	}
}

// TestTheProcessWideHookLandsInThisSession'sRegistry — spelled without the
// apostrophe below — installs the handler exactly as runBrowse does and
// fires it the way pelican's oauth2 does, so what is tested is the wiring
// and not a direct call to Add.
func TestTheProcessWideHookLandsInThisSessionsRegistry(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	restore := installPromptHandler(f.bs)
	defer restore()
	// Two flows, on two goroutines, exactly as two namespaces would.
	var wg sync.WaitGroup
	for _, code := range []string{"AAAA-BBBB", "CCCC-DDDD"} {
		wg.Add(1)
		go func(code string) {
			defer wg.Done()
			fireVerificationHandler("https://login.example.edu/device", code)
		}(code)
	}
	wg.Wait()
	if c := f.bs.prompts.Cards(); len(c) != 2 {
		t.Fatalf("%d cards from two concurrent device flows through the process-wide hook", len(c))
	}
	// Uninstalled on the way out: a `pelfs mount` in this process must keep
	// the terminal behaviour.
	restore()
	fireVerificationHandler("https://login.example.edu/device", "EEEE-FFFF")
	if c := f.bs.prompts.Cards(); len(c) != 2 {
		t.Fatalf("a prompt arrived after the handler was removed: %+v", c)
	}
}
