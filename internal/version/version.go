// Package version holds the Muninn release identifier.
package version

// Version is the current Muninn release. Release builds may override via:
//
//	-ldflags="-X github.com/skaldlab/muninn/internal/version.Version=x.y.z"
var Version = "0.3.0"
