// Command adb-broker mediates read-only, audited access to a phone's media over the adb
// sync protocol.
//
// Everything it does lives in app/broker. This file exists only to bind that package to the
// process: it is deliberately the smallest thing that can be written, because code here is
// code that cannot be tested in process.
package main

import (
	"os"

	"github.com/jroedel/adb-broker/app/broker"
)

// main hands argv, without the program name, and the two output streams to broker.Main and
// exits with the status it returns.
//
// os.Args and os.Exit are named here and nowhere else. That is what lets every subcommand be
// exercised in a test by calling broker.Main with a slice and two buffers — a binary whose
// behaviour is reachable only by spawning it is a binary whose wire format is asserted
// loosely, if at all.
func main() {
	os.Exit(broker.Main(os.Args[1:], os.Stdout, os.Stderr))
}
