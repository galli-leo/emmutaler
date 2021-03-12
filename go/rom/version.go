package rom

import (
	"log"
	"regexp"
	"strconv"
)

var vt8030 = VersionInfo{4479, 100, 4}

type VersionInfo struct {
	Major uint64
	Minor uint64
	Patch uint64
}

// TODO: Do Patch comparision.
func (v *VersionInfo) Less(other *VersionInfo) bool {
	return v.Major < other.Major || (v.Major == other.Major && v.Minor < other.Minor)
}

var versionRegex = regexp.MustCompile(`iBoot-(\d+)\.0\.0\.(\d+)\.(\d+)`)

func mustParseUint(inp string) uint64 {
	ret, err := strconv.ParseUint(inp, 10, 64)
	if err != nil {
		panic("Failed to parse integer")
	}
	return ret
}

func (r *ROM) ParseVersion() {
	matches := versionRegex.FindStringSubmatch(r.meta.BuildInfo.Tag)
	log.Printf("TAG: %s", r.meta.BuildInfo.Tag)
	major, minor, patch := matches[1], matches[2], matches[3]
	r.version = VersionInfo{
		Major: mustParseUint(major),
		Minor: mustParseUint(minor),
		Patch: mustParseUint(patch),
	}
}
