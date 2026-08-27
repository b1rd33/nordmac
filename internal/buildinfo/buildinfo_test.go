package buildinfo

import "testing"

func TestString(t *testing.T) {
	version, commit, date := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = version, commit, date })
	Version, Commit, Date = "0.1.0", "abc123", "2026-08-27"

	want := "nordmac 0.1.0 (commit abc123, built 2026-08-27)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
