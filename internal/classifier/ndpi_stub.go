//go:build !ndpi
// +build !ndpi

// Package classifier — stub used in default (non-cgo) builds. Keeps
// `main.go` and the rest of the tree compilable without libndpi
// installed; `NewNDPIClassifier` always returns an error so the
// runtime falls back to the port-based classifier.
//
// To enable real nDPI: `go build -tags ndpi ./...` (requires
// libndpi-dev at build time, libndpi at runtime).
package classifier

import "errors"

// NDPIClassifier is the no-op shape so call sites compile without the
// `ndpi` build tag.
type NDPIClassifier struct{}

// NewNDPIClassifier always errors out in stub builds; callers should
// inspect the error and fall back to NewPortClassifier.
func NewNDPIClassifier(maxFlows, idleSeconds int) (*NDPIClassifier, error) {
	return nil, errors.New("nDPI support not compiled in (build with `-tags ndpi`)")
}

// Classify is unreachable in stub builds (constructor always errors)
// but satisfies the Classifier interface for compile-time symmetry.
func (c *NDPIClassifier) Classify(srcIP, dstIP []byte, srcPort, dstPort uint16, transportProto uint8, ipPacket []byte) Result {
	return Result{Protocol: "other"}
}

// Close is a no-op in stub builds.
func (c *NDPIClassifier) Close() {}

// FlowCount is always zero in stub builds.
func (c *NDPIClassifier) FlowCount() int { return 0 }

// ProtocolCategories is empty in stub builds.
func (c *NDPIClassifier) ProtocolCategories() []ProtocolCategory { return nil }

// NDPIAvailable signals at compile time whether the binary was built
// with `-tags ndpi`. False here; the cgo file defines it as true.
const NDPIAvailable = false
