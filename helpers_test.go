package main

import (
	"slices"
	"testing"
)

func TestSharedMaskEchoSemantics(t *testing.T) {
	// Initial choice, coerced zero, absence, real replacement, then candidate-only
	// submission: the last shared mask clears the old delegate choice.
	c := [][]int{{0}, {zeroSubmission}, {noSubmission}, {2}, {1}}
	d := [][]int{{1}, {zeroSubmission}, {noSubmission}, {0}, {noSubmission}}
	if got, want := periodicEchoTotalsPlain(c, d, 1, 3), []uint64{3, 1, 1}; !slices.Equal(got, want) {
		t.Fatalf("candidate echo: got %v want %v", got, want)
	}
	if got, want := periodicEchoTotalsPlain(d, c, 1, 2), []uint64{1, 3}; !slices.Equal(got, want) {
		t.Fatalf("delegate echo: got %v want %v", got, want)
	}
}

func TestSharedMaskWithZeroComponent(t *testing.T) {
	cp, cm := periodPlain([]int{noSubmission}, []int{1}, 1, 3)
	dp, dm := periodPlain([]int{1}, []int{noSubmission}, 1, 2)
	if !slices.Equal(cp, []uint64{0, 0, 0}) || !slices.Equal(cm, []uint64{1, 1, 1}) ||
		!slices.Equal(dp, []uint64{0, 1}) || !slices.Equal(dm, []uint64{1, 1}) {
		t.Fatalf("wrong shared-mask submission: %v %v %v %v", cp, cm, dp, dm)
	}
	for _, choice := range []int{noSubmission, zeroSubmission} {
		payload, mask := periodPlain([]int{choice}, []int{choice}, 1, 3)
		if !slices.Equal(payload, []uint64{0, 0, 0}) || !slices.Equal(mask, []uint64{0, 0, 0}) {
			t.Fatalf("zero input changed state: %v %v", payload, mask)
		}
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

func periodicEchoTotalsPlainTree(choices, otherChoices [][]int, voterCount, width int) []uint64 {
	out := make([]uint64, voterCount*width)
	for voter := range voterCount {
		for slot := range width {
			segments := make([]plainEchoSegment, len(choices))
			for period := range choices {
				x, z := 0, 0
				if submissionMask(choices[period][voter], otherChoices[period][voter]) == 1 {
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
	other := [][]int{{1, -1}, {zeroSubmission, -1}, {-1, 2}, {0, zeroSubmission}, {2, 1}}
	choices[1][0], choices[3][1] = zeroSubmission, zeroSubmission
	sequential := periodicEchoTotalsPlain(choices, other, 2, 3)
	balanced := periodicEchoTotalsPlainTree(choices, other, 2, 3)
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
	candidatePeriods[1][0], delegationPeriods[1][0] = zeroSubmission, zeroSubmission
	candidatePeriods[2][1], delegationPeriods[2][1] = zeroSubmission, zeroSubmission
	candidatePeriods[3][2], delegationPeriods[3][2] = zeroSubmission, zeroSubmission
	q := []uint64{1, 3, 2}

	v := periodicEchoTotalsPlain(candidatePeriods, delegationPeriods, n, b)
	d := periodicEchoTotalsPlain(delegationPeriods, candidatePeriods, n, k)
	want := delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T)
	got := delegatedMaskedTallyFromPeriodsPlain(
		D, candidatePeriods, delegationPeriods, q, n, b, k, T,
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
