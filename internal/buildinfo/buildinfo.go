// Package buildinfo exposes release metadata injected by GoReleaser.
package buildinfo

import "fmt"

var (
	Version      = "dev"
	Commit       = "unknown"
	Date         = "unknown"
	HelperSHA256 = ""
)

type Info struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	Date         string `json:"date"`
	HelperSHA256 string `json:"helper_sha256,omitempty"`
}

func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date, HelperSHA256: HelperSHA256}
}

// String returns a stable, human-readable version line.
func String() string {
	return fmt.Sprintf("nordmac %s (commit %s, built %s)", Version, Commit, Date)
}
