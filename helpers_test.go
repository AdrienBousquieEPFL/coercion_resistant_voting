package main

import (
	"slices"
	"testing"
)

func TestRegistrationValidityBitsAreSharedByVoterPeriod(t *testing.T) {
	validity := registrationValidityBits(3, 2)
	if len(validity) != 3 {
		t.Fatalf("period count: got %d, want 3", len(validity))
	}
	for period := range validity {
		if !slices.Equal(validity[period], []uint64{1, 1}) {
			t.Fatalf("period %d validity: got %v, want [1 1]", period, validity[period])
		}
	}

	// One voter-period bit is consumed by both independent plaintext
	// references, mirroring reuse of one ciphertext by both encrypted paths.
	validity[1][0] = 0
	candidate := [][]int{{0, -1}, {1, -1}, {2, -1}}
	delegation := [][]int{{1, -1}, {0, -1}, {2, -1}}
	if got, want := periodicEchoTotalsPlain(candidate, validity, 2, 3), []uint64{2, 0, 1, 0, 0, 0}; !slices.Equal(got, want) {
		t.Fatalf("candidate echo: got %v, want %v", got, want)
	}
	if got, want := periodicEchoTotalsPlain(delegation, validity, 2, 3), []uint64{0, 2, 1, 0, 0, 0}; !slices.Equal(got, want) {
		t.Fatalf("delegation echo: got %v, want %v", got, want)
	}
}

func TestSharedValidityAllowsOneAbsentComponent(t *testing.T) {
	validity := []uint64{1}
	candidatePayload, candidateMask := gatedPeriodPlain([]int{-1}, validity, 1, 3)
	delegationPayload, delegationMask := gatedPeriodPlain([]int{1}, validity, 1, 2)

	if !slices.Equal(candidatePayload, []uint64{0, 0, 0}) || !slices.Equal(candidateMask, []uint64{0, 0, 0}) {
		t.Fatalf("absent candidate component must remain zero: payload=%v mask=%v", candidatePayload, candidateMask)
	}
	if !slices.Equal(delegationPayload, []uint64{0, 1}) || !slices.Equal(delegationMask, []uint64{1, 1}) {
		t.Fatalf("present delegation component was not gated correctly: payload=%v mask=%v", delegationPayload, delegationMask)
	}
}

type plainEchoSegment struct {
	a, b, c, d int
}

func composePlainEcho(left, right plainEchoSegment) plainEchoSegment {
	return plainEchoSegment{
		a: right.a * left.a,
		b: right.a*left.b + right.b,
		c: left.c + right.c*left.a,
		d: left.d + right.d + right.c*left.b,
	}
}

func periodicEchoTotalsPlainTree(choices [][]int, validity [][]uint64, voterCount, width int) []uint64 {
	out := make([]uint64, voterCount*width)
	for voter := range voterCount {
		for slot := range width {
			segments := make([]plainEchoSegment, len(choices))
			for period := range choices {
				x, z := 0, 0
				if choices[period][voter] >= 0 && validity[period][voter] == 1 {
					z = 1
					if choices[period][voter] == slot {
						x = 1
					}
				}
				a := 1 - z
				segments[period] = plainEchoSegment{a: a, b: x, c: a, d: x}
			}
			out[voter*width+slot] = uint64(balancedReduce(segments, composePlainEcho).d)
		}
	}
	return out
}

func TestBalancedAndSequentialEchoAgree(t *testing.T) {
	choices := [][]int{
		{0, 2},
		{1, -1},
		{-1, 1},
		{2, 0},
		{1, 2},
	}
	validity := [][]uint64{
		{1, 1},
		{0, 1}, // invalid replacement for voter zero; voter one is absent
		{1, 1},
		{1, 0}, // invalid replacement for voter one
		{1, 1},
	}
	sequential := periodicEchoTotalsPlain(choices, validity, 2, 3)
	balanced := periodicEchoTotalsPlainTree(choices, validity, 2, 3)
	if !slices.Equal(balanced, sequential) {
		t.Fatalf("balanced echo %v differs from sequential echo %v", balanced, sequential)
	}
}

func TestStreamingFinalReferenceMatchesMaterializedReference(t *testing.T) {
	const (
		n = 3
		b = 3
		k = 2
		T = 5
	)
	D := [][]uint64{
		{1, 0},
		{0, 1},
		{1, 0},
	}
	candidatePeriods := [][]int{
		{0, 1, 2},
		{1, -1, 2},
		{-1, 2, 1},
		{2, 2, -1},
		{2, 0, 1},
	}
	delegationPeriods := [][]int{
		{-1, 0, 1},
		{0, 0, -1},
		{-1, 1, 1},
		{1, -1, 0},
		{-1, 1, 0},
	}
	validity := [][]uint64{
		{1, 1, 1},
		{0, 1, 1},
		{1, 0, 1},
		{1, 1, 0},
		{1, 1, 1},
	}
	q := []uint64{1, 3, 2}

	v := periodicEchoTotalsPlain(candidatePeriods, validity, n, b)
	d := periodicEchoTotalsPlain(delegationPeriods, validity, n, k)
	want := delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T)
	got := delegatedMaskedTallyFromPeriodsPlain(
		D, candidatePeriods, delegationPeriods, validity, q, n, b, k, T,
	)
	if !slices.Equal(got, want) {
		t.Fatalf("streaming final reference: got %v, want %v", got, want)
	}
}

func TestPackingLayoutCrossesCiphertextBoundary(t *testing.T) {
	const blockWidth = 5
	const rows = 2
	const columns = 8192
	votersPerCiphertext := rows * (columns / blockWidth)

	full := computePackingLayout(votersPerCiphertext, blockWidth, rows, columns)
	if full.ciphertextCount != 1 {
		t.Fatalf("full ciphertext count: got %d, want 1", full.ciphertextCount)
	}

	overflow := computePackingLayout(votersPerCiphertext+1, blockWidth, rows, columns)
	if overflow.ciphertextCount != 2 {
		t.Fatalf("boundary ciphertext count: got %d, want 2", overflow.ciphertextCount)
	}
	if overflow.votersPerCiphertext != votersPerCiphertext {
		t.Fatalf("voters per ciphertext: got %d, want %d", overflow.votersPerCiphertext, votersPerCiphertext)
	}
}
