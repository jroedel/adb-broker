//go:build fixture

package broker

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/stores/fixturedb"
)

// A fixture binary must not be able to answer "what are you" with the plain release version.
// That is the whole reason the suffix exists — a fixture build sitting in a production path is
// meant to be visible rather than indistinguishable — and version is the one path that reports
// a version without building a Store, so it is the one path where nothing appends the mark for
// it. This file exists only under the fixture tag, because that is the only build where there
// is anything to assert.
func TestFixtureVersionCarriesTheSuffixExactlyOnce(t *testing.T) {
	swap(t, &version, "9.9.9")

	var stdout, stderr bytes.Buffer

	if exit := Main([]string{"version"}, &stdout, &stderr); exit != exitOK {
		t.Fatalf("exit = %d, want %d; stderr: %s", exit, exitOK, stderr.String())
	}

	got := decode(t, lines(t, stdout.String())[0])

	broker, _ := got["broker"].(string)

	// Once, not twice. "0.1.0+fixture+fixture" is a bug this codebase has already had: the
	// suffix was applied both by fixturedb.NewStore and by the app layer. runVersion is the
	// one caller allowed to apply it, precisely because it never reaches NewStore.
	switch {
	case broker != "9.9.9"+fixturedb.VersionSuffix:
		t.Errorf("broker = %q, want %q", broker, "9.9.9"+fixturedb.VersionSuffix)

	case strings.Count(broker, fixturedb.VersionSuffix) != 1:
		t.Errorf("broker = %q carries %q more than once", broker, fixturedb.VersionSuffix)
	}
}
