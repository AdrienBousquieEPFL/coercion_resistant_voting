package main

import (
	"fmt"
	"math/bits"
	"slices"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestIncrementalTreePreservesExactBatchGrouping(t *testing.T) {
	for count := 1; count <= 65; count++ {
		leaves := make([]string, count)
		combine := func(a, b string) string { return "(" + a + "," + b + ")" }
		merges := 0
		r := incrementalBalanced[string]{total: count, combine: func(a, b string) string { merges++; return combine(a, b) }}
		for i := range leaves {
			leaves[i] = fmt.Sprint(i)
			r.Push(leaves[i])
			if count == 5 && merges != []int{0, 1, 2, 2, 4}[i] {
				t.Fatalf("period %d: merge was not performed at subtree close", i)
			}
			if len(r.frontier) > bits.Len(uint(count))+1 {
				t.Fatalf("unbounded frontier at count=%d", count)
			}
		}
		if got, want := r.Result(), balancedReduce(leaves, combine); got != want {
			t.Fatalf("count=%d got %s want %s", count, got, want)
		}
		if merges != count-1 {
			t.Fatalf("count=%d merges=%d", count, merges)
		}
	}
}

// Small, deliberately insecure ring for functional tests only. The wide voter
// blocks force both slot rows and two ciphertexts, including padding slots.
func TestPeriodStreamingEncryptedEcho(t *testing.T) {
	params := must1(bgv.NewParametersFromLiteral(bgv.ParametersLiteral{LogN: 10, LogQ: []int{50, 50, 50, 50, 50, 50, 50, 50}, LogP: []int{50}, PlaintextModulus: 65537}))
	encoder := bgv.NewEncoder(params)
	kg := rlwe.NewKeyGenerator(params)
	sk, pk := kg.GenKeyPairNew()
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)
	evaluator := bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(kg.GenRelinearizationKeyNew(sk)), true)
	const n, b, k, T = 5, 200, 3, 5
	layout := computePackingLayout(n, b, 2, params.MaxSlots()/2)
	choices := [][]int{{0, 1, -1, 199, 0}, {1, -1, -1, 0, 1}, {-1, 2, -1, -1, 2}, {2, -1, -1, 1, -1}, {-1, 0, -1, -1, 0}}
	delegation := [][]int{{1, -1, -1, 0, 2}, {-1, 0, -1, 1, 0}, {2, -1, -1, -1, 1}, {-1, 1, -1, 2, -1}, {0, -1, -1, -1, 2}}
	validity := registrationValidityBits(T, n)
	validity[1][0] = 0
	validity[3][3] = 0
	logical := func(width int) [][]uint64 {
		out := make([][]uint64, layout.ciphertextCount)
		for i := range out {
			out[i] = make([]uint64, params.MaxSlots())
			for local := 0; local < min(layout.votersPerCiphertext, n-i*layout.votersPerCiphertext); local++ {
				base := local/layout.votersPerRow*layout.colsPerCiphertext + local%layout.votersPerRow*b
				for j := range width {
					out[i][base+j] = 1
				}
			}
		}
		return out
	}
	check := func(cts []*rlwe.Ciphertext, plain []uint64, width int) {
		t.Helper()
		for i, ct := range cts {
			got := make([]uint64, params.MaxSlots())
			must(encoder.Decode(decryptor.DecryptNew(ct), got))
			want := make([]uint64, params.MaxSlots())
			for local := 0; local < min(layout.votersPerCiphertext, n-i*layout.votersPerCiphertext); local++ {
				voter := i*layout.votersPerCiphertext + local
				base := local/layout.votersPerRow*layout.colsPerCiphertext + local%layout.votersPerRow*b
				copy(want[base:base+width], plain[voter*width:(voter+1)*width])
			}
			if !slices.Equal(got, want) {
				t.Fatalf("decoded packed block %d differs from reference", i)
			}
		}
	}
	type pair struct {
		c, d          *periodicEchoState
		refreshes     *int
		wantRefreshes int
	}
	states := []pair{}
	for _, interval := range []int{-1, 0, 2, 3} { // -1: sequential without refresh
		count := new(int)
		mode := "sequential"
		if interval == 0 {
			mode = "tree"
		}
		newState := func() *periodicEchoState {
			return newPeriodicEchoState(T, layout.ciphertextCount, mode, evaluator, func(p int) bool { return interval > 0 && p < T-1 && p%interval == 0 }, func(ct *rlwe.Ciphertext) *rlwe.Ciphertext {
				// Isolate scheduling here; full multiparty refresh is checked by CLI smokes.
				*count++
				return must1(encryptor.EncryptNew(decryptor.DecryptNew(ct)))
			})
		}
		wantRefreshes := 0
		if interval > 0 {
			wantRefreshes = 2 * layout.ciphertextCount
		}
		states = append(states, pair{newState(), newState(), count, wantRefreshes})
	}
	for p := range T {
		a := streamAndAggregatePeriodInputs(params, encoder, encryptor, evaluator, layout, b, b, k, n, T, p, choices, delegation, validity, 0, nil)
		cp, cm := gatedPeriodPlain(choices[p], validity[p], n, b)
		dp, dm := gatedPeriodPlain(delegation[p], validity[p], n, k)
		check(a.candidateInputs, cp, b)
		check(a.candidateRangeMasks, cm, b)
		check(a.delegationInputs, dp, k)
		check(a.delegationRangeMasks, dm, k)
		for _, state := range states {
			state.c.ClosePeriod(a.candidateInputs, a.candidateRangeMasks, logical(b))
			state.d.ClosePeriod(a.delegationInputs, a.delegationRangeMasks, logical(k))
			if state.c.mode == "sequential" {
				check(state.c.totals, periodicEchoTotalsPlain(choices[:p+1], validity[:p+1], n, b), b)
				check(state.d.totals, periodicEchoTotalsPlain(delegation[:p+1], validity[:p+1], n, k), k)
			}
		}
	}
	for _, state := range states {
		check(state.c.Totals(), periodicEchoTotalsPlain(choices, validity, n, b), b)
		check(state.d.Totals(), periodicEchoTotalsPlain(delegation, validity, n, k), k)
		expected := state.wantRefreshes
		if *state.refreshes != expected {
			t.Fatalf("refresh calls: got %d want %d", *state.refreshes, expected)
		}
	}
	// Benchmark ingress is confined to period zero, but every period is closed.
	fixture := prepareBenchmarkInputCiphertexts(params, encoder, encryptor)
	state := newPeriodicEchoState(T, layout.ciphertextCount, "tree", evaluator, nil, nil)
	for p := range T {
		a := streamAndAggregatePeriodInputs(params, encoder, encryptor, evaluator, layout, b, b, k, n, T, p, nil, nil, nil, n, fixture)
		expected := 0
		if p == 0 {
			expected = n
		}
		if a.validityCiphertextCount != expected {
			t.Fatalf("benchmark period %d processed %d validity inputs", p, a.validityCiphertextCount)
		}
		check(a.candidateInputs, make([]uint64, n*b), b)
		state.ClosePeriod(a.candidateInputs, a.candidateRangeMasks, logical(b))
	}
	check(state.Totals(), make([]uint64, n*b), b)
}
