package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// incrementalBalanced preserves balancedReduce's midpoint split, including for
// non-power-of-two period counts. A node is merged as soon as its rightmost
// leaf arrives. The frontier holds only O(log(total)) completed subtrees.
// Push transfers ownership of the value; combine must not mutate its operands.
type incrementalBalanced[T any] struct {
	total, received int
	frontier        []T
	combine         func(T, T) T
}

func (r *incrementalBalanced[T]) Push(value T) {
	assert(r.total > 0 && r.received < r.total, "too many tree leaves")
	r.frontier = append(r.frontier, value)
	// Every ancestor ending at this leaf has just received its right child.
	// Count those ancestors along the original midpoint-tree path.
	merges := 0
	for lo, hi := 0, r.total-1; lo < hi; {
		if hi == r.received {
			merges++
		}
		mid := (lo + hi) / 2
		if r.received <= mid {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	for range merges {
		n := len(r.frontier)
		merged := r.combine(r.frontier[n-2], r.frontier[n-1])
		var zero T
		r.frontier[n-1] = zero // release pointers outside the shortened slice
		r.frontier[n-2] = merged
		r.frontier = r.frontier[:n-1]
	}
	r.received++
}

func (r *incrementalBalanced[T]) Result() T {
	assert(r.received == r.total && len(r.frontier) == 1, "tree is incomplete")
	return r.frontier[0]
}

// echoSegment represents u'=a*u+b and total'=total+c*u+d.
type echoSegment struct{ a, b, c, d *rlwe.Ciphertext }

type periodicEchoState struct {
	periods, received, blocks int
	mode                      string
	evaluator                 *bgv.Evaluator
	tree                      incrementalBalanced[[]echoSegment]
	current, totals           []*rlwe.Ciphertext
	shouldRefresh             func(int) bool
	refresh                   func(*rlwe.Ciphertext) *rlwe.Ciphertext
}

func newPeriodicEchoState(periods, blocks int, mode string, evaluator *bgv.Evaluator, shouldRefresh func(int) bool, refresh func(*rlwe.Ciphertext) *rlwe.Ciphertext) *periodicEchoState {
	assert(periods > 0 && blocks > 0, "echo requires periods and ciphertext blocks")
	assert(mode == "tree" || mode == "sequential", "invalid echo mode")
	s := &periodicEchoState{periods: periods, blocks: blocks, mode: mode, evaluator: evaluator, shouldRefresh: shouldRefresh, refresh: refresh}
	s.tree = incrementalBalanced[[]echoSegment]{total: periods, combine: func(left, right []echoSegment) []echoSegment {
		out := make([]echoSegment, blocks)
		for i := range out {
			l, r := left[i], right[i]
			a := s.mul(r.a, l.a)
			b := s.add(s.mul(r.a, l.b), r.b)
			c := s.add(l.c, s.mul(r.c, l.a))
			d := s.add(s.add(l.d, r.d), s.mul(r.c, l.b))
			out[i] = echoSegment{a, b, c, d}
		}
		return out
	}}
	return s
}

func (s *periodicEchoState) mul(left, right *rlwe.Ciphertext) *rlwe.Ciphertext {
	CountOp("MulRelinNew")
	out := must1(s.evaluator.MulRelinNew(left, right))
	assert(out.Level() == min(left.Level(), right.Level()), "scale-invariant echo multiplication must preserve the minimum input level")
	return out
}
func (s *periodicEchoState) add(left, right *rlwe.Ciphertext) *rlwe.Ciphertext {
	CountOp("AddNew")
	return must1(s.evaluator.AddNew(left, right))
}

// ClosePeriod consumes one packed period's gated payload and mask. No input
// ciphertext may be mutated by the caller afterward: tree leaves can own them.
func (s *periodicEchoState) ClosePeriod(inputs, masks []*rlwe.Ciphertext, logicalRanges [][]uint64) {
	assert(s.received < s.periods, "too many echo periods")
	assert(len(inputs) == s.blocks && len(masks) == s.blocks && len(logicalRanges) == s.blocks, "echo packing mismatch")
	oneMinus := make([]*rlwe.Ciphertext, s.blocks)
	for i := range oneMinus {
		CountOp("MulNew")
		neg := must1(s.evaluator.MulNew(masks[i], -1))
		CountOp("AddNew")
		oneMinus[i] = must1(s.evaluator.AddNew(neg, logicalRanges[i]))
	}
	if s.mode == "tree" {
		leaves := make([]echoSegment, s.blocks)
		for i := range leaves {
			leaves[i] = echoSegment{oneMinus[i], inputs[i], oneMinus[i], inputs[i]}
		}
		s.tree.Push(leaves)
	} else if s.received == 0 {
		s.current = make([]*rlwe.Ciphertext, s.blocks)
		s.totals = make([]*rlwe.Ciphertext, s.blocks)
		for i := range inputs {
			s.current[i] = inputs[i].CopyNew()
			s.totals[i] = inputs[i].CopyNew()
		}
	} else {
		for i := range inputs {
			carried := s.mul(s.current[i], oneMinus[i])
			s.current[i] = s.add(carried, inputs[i])
			CountOp("Add")
			must(s.evaluator.Add(s.totals[i], s.current[i], s.totals[i]))
		}
		if s.shouldRefresh != nil && s.shouldRefresh(s.received) {
			CountOp("SequentialStateRefreshBoundary")
			for i := range s.current {
				s.current[i] = s.refresh(s.current[i])
			}
		}
	}
	s.received++
}

func (s *periodicEchoState) Totals() []*rlwe.Ciphertext {
	assert(s.received == s.periods, "echo is incomplete")
	if s.mode == "sequential" {
		return s.totals
	}
	root := s.tree.Result()
	totals := make([]*rlwe.Ciphertext, s.blocks)
	for i := range totals {
		totals[i] = root[i].d
	}
	return totals
}
