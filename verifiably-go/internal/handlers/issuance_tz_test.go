package handlers

import "testing"

// A datetime-local / date input carries no zone. Interpreting it as UTC pins a
// user's local wall-clock to UTC, pushing validFrom into the future for a
// UTC+offset operator and tripping the verifier's not-before gate. The offset
// (minutes EAST of UTC, from the issue form's timezone selector) must be applied
// before converting to UTC; an RFC3339 input keeps its own explicit zone.
func TestNormalizeIssuanceTimeTZ(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		offsetMin int
		want      string
	}{
		{"datetime-local UTC+5:30", "2026-07-07T17:36", 330, "2026-07-07T12:06:00Z"},
		{"datetime-local UTC", "2026-07-07T17:36", 0, "2026-07-07T17:36:00Z"},
		{"datetime-local west UTC-5", "2026-07-07T09:00", -300, "2026-07-07T14:00:00Z"},
		{"with seconds UTC+5:30", "2026-07-07T17:36:45", 330, "2026-07-07T12:06:45Z"},
		{"date-only UTC+5:30 rolls back a day", "2026-07-07", 330, "2026-07-06T18:30:00Z"},
		{"RFC3339 keeps its own zone (offset ignored)", "2026-07-07T17:36:00-05:00", 330, "2026-07-07T22:36:00Z"},
		{"blank", "", 330, ""},
		{"garbage", "not a time", 330, ""},
	}
	for _, c := range cases {
		if got := normalizeIssuanceTimeTZ(c.in, c.offsetMin); got != c.want {
			t.Errorf("%s: normalizeIssuanceTimeTZ(%q, %d) = %q, want %q", c.name, c.in, c.offsetMin, got, c.want)
		}
	}
	// The zero-offset wrapper stays backwards-compatible.
	if got := normalizeIssuanceTime("2026-07-07T17:36"); got != "2026-07-07T17:36:00Z" {
		t.Errorf("normalizeIssuanceTime wrapper = %q, want 2026-07-07T17:36:00Z", got)
	}
}
