package rawfuse

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// A workload that trips the EIO path trips it per operation. Suppressed
// occurrences must cost nothing -- no formatting, no frame lookup, no
// allocation -- and the count must survive into the next line that gets
// through, since that count is the only remaining signal that the
// failure was in bulk.
func TestEIOReportIsRateLimitedAndFree(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()

	eioReportedAt.Store(time.Now().UnixNano())
	eioSuppressed.Store(0)
	err := errors.New("something the binding cannot translate")

	if n := testing.AllocsPerRun(200, func() { logUnexpected(err) }); n != 0 {
		t.Errorf("suppressed EIO report allocates %v times per call", n)
	}
	if out.Len() != 0 {
		t.Errorf("reported inside the rate-limit window: %q", out.String())
	}
	suppressed := eioSuppressed.Load()
	if suppressed == 0 {
		t.Fatal("nothing was counted as suppressed")
	}

	eioReportedAt.Store(0)
	logUnexpected(err)
	line := out.String()
	if !strings.Contains(line, "returning EIO for an unrecognized error") {
		t.Errorf("no report after the window: %q", line)
	}
	if !strings.Contains(line, "more like it") {
		t.Errorf("report dropped the suppressed count: %q", line)
	}
	if eioSuppressed.Load() != 0 {
		t.Errorf("suppressed count not cleared by the report")
	}
}
