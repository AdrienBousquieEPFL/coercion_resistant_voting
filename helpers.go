package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// pickPlaintextModulus returns the smallest NTT-friendly prime t such that
// t >= n, where t ≡ 1 (mod 2N) with N = 1<<logN.
func pickPlaintextModulus(n uint64, logN int) uint64 {
	twoN := uint64(1) << (logN + 1)
	p := twoN + 1
	for p < n {
		p += twoN
	}
	for !ring.IsPrime(p) {
		p += twoN
	}
	return p
}

// must/assert panic instead of log.Fatal so the deferred crash handler in
// main runs and can dump a crash.json before the process exits.
func must(err error) {
	if err != nil {
		panic(fmt.Errorf("must: %w", err))
	}
}

func must1[T any](v T, err error) T {
	must(err)
	return v
}

func assert(cond bool, msg string) {
	if !cond {
		panic("assertion failed: " + msg)
	}
}

func randUint64n(n uint64) uint64 {
	assert(n > 0, "randUint64n requires n > 0")

	limit := ^uint64(0) - (^uint64(0) % n)
	var buf [8]byte

	for {
		must1(cryptorand.Read(buf[:]))
		x := binary.LittleEndian.Uint64(buf[:])
		if x < limit {
			return x % n
		}
	}
}

// randomDelegationMatrix returns an n x k one-hot matrix.
// This is a mapping from a delegate index to a voter index where it's a one-to-one function
func randomDelegationMatrix(n, k int) [][]uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(k > 0, "k must be > 0")
	assert(k < n, "k must be < n")

	d := make([][]uint64, n)
	for i := 0; i < n; i++ {
		d[i] = make([]uint64, k)
	}

	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}

	for i := 0; i < k; i++ {
		j := i + int(randUint64n(uint64(n-i)))
		perm[i], perm[j] = perm[j], perm[i]
		voterIdx := perm[i]
		d[voterIdx][i] = 1
	}

	return d
}

// randomDelegationVector returns a flattened row-major matrix where each row
// sums to a value in [0, T]. Each row independently has probability 1/2 of
// containing one entry > floor(T/2), so the expected number of selected rows is
// rowCount/2 after applying I(x > floor(T/2)).
func randomDelegationVector(rowCount, colCount, T int) []uint64 {
	assert(rowCount >= 0, "rowCount must be >= 0")
	assert(colCount > 0, "colCount must be > 0")
	assert(T >= 0, "T must be >= 0")

	v := make([]uint64, rowCount*colCount)
	threshold := T / 2
	for i := range rowCount {
		rowOffset := i * colCount

		if T > 0 && randUint64n(2) == 1 {
			majorityCol := int(randUint64n(uint64(colCount)))
			majorityValue := threshold + 1 + int(randUint64n(uint64(T-threshold)))
			v[rowOffset+majorityCol] = uint64(majorityValue)

			remaining := int(randUint64n(uint64(T - majorityValue + 1)))
			for j := 0; j < remaining; j++ {
				col := int(randUint64n(uint64(colCount)))
				v[rowOffset+col]++
			}
			continue
		}

		rowTotal := int(randUint64n(uint64(threshold + 1)))
		for j := 0; j < rowTotal; j++ {
			col := int(randUint64n(uint64(colCount)))
			v[rowOffset+col]++
		}
	}

	return v
}

// randomVotingVector returns a flattened row-major matrix where each
// row sums to T and has one randomly chosen entry >= ceil(T/2).
func randomVotingVector(rowCount, colCount, T int) []uint64 {
	assert(rowCount >= 0, "rowCount must be >= 0")
	assert(colCount > 0, "colCount must be > 0")
	assert(T > 0, "T must be > 0")

	v := make([]uint64, rowCount*colCount)
	threshold := ceilDiv(T, 2)

	for i := range rowCount {
		majorityCol := int(randUint64n(uint64(colCount)))
		v[i*colCount+majorityCol] = uint64(threshold)

		remaining := T - threshold
		for j := 0; j < remaining; j++ {
			col := int(randUint64n(uint64(colCount)))
			v[i*colCount+col]++
		}
	}

	return v
}

// randomVotingPower returns each voter's initial voting power q_i, drawn
// uniformly from [1, qMax]. qMax=1 yields the unweighted all-ones vector, which
// reproduces the behaviour of the pipeline before per-voter power was added.
func randomVotingPower(voterCount, qMax int) []uint64 {
	assert(voterCount >= 0, "voterCount must be >= 0")
	assert(qMax > 0, "qMax must be > 0")

	q := make([]uint64, voterCount)
	for i := range q {
		q[i] = 1 + randUint64n(uint64(qMax))
	}
	return q
}

// periodicChoicesFromCounts expands a row-major voter-by-choice count vector
// into a period-major submission schedule. A value of -1 means that the voter
// submits no new input in that period. Counts are drained in column order; the
// order is immaterial before echo semantics are introduced, but the returned
// schedule makes that order explicit for the encrypted periodic update.
func periodicChoicesFromCounts(counts []uint64, voterCount, width, periods int) [][]int {
	assert(voterCount >= 0, "voterCount must be >= 0")
	assert(width > 0, "width must be > 0")
	assert(periods > 0, "periods must be > 0")
	assert(len(counts) == voterCount*width, "len(counts) must be voterCount*width")

	remaining := append([]uint64(nil), counts...)
	choices := make([][]int, periods)
	for period := range choices {
		choices[period] = make([]int, voterCount)
		for voter := range voterCount {
			choices[period][voter] = drainOneHot(remaining, voter, width)
		}
	}

	for _, left := range remaining {
		assert(left == 0, "input row contains more submissions than periods")
	}
	return choices
}

// ensureEchoCarryEvent guarantees that a simulation with at least two periods
// contains a no-submission event immediately after a concrete submission. If
// two adjacent submissions already make the same choice, replacing the second
// with an echo preserves the effective per-period plaintext totals exactly.
// The fallback creates a simple choice-then-echo sequence for voter zero.
func ensureEchoCarryEvent(choices [][]int) {
	if len(choices) < 2 || len(choices[0]) == 0 {
		return
	}

	for voter := range choices[0] {
		for period := 1; period < len(choices); period++ {
			if choices[period-1][voter] >= 0 && choices[period][voter] == choices[period-1][voter] {
				choices[period][voter] = -1
				return
			}
		}
	}

	choices[0][0] = 0
	choices[1][0] = -1
}

// periodicEchoTotalsPlain evaluates the plaintext counterpart of
// u^p = u^(p-1)*(1-z^p) + input^p and sums every u^p. Each schedule entry is a
// one-hot choice index, or -1 when the voter submits nothing and their previous
// value is therefore carried forward.
func periodicEchoTotalsPlain(choices [][]int, voterCount, width int) []uint64 {
	assert(voterCount >= 0, "voterCount must be >= 0")
	assert(width > 0, "width must be > 0")
	assert(len(choices) > 0, "choices must contain at least one period")

	current := make([]int, voterCount)
	for voter := range current {
		current[voter] = -1
	}
	out := make([]uint64, voterCount*width)

	for _, periodChoices := range choices {
		assert(len(periodChoices) == voterCount, "each period must contain one entry per voter")
		for voter, choice := range periodChoices {
			assert(choice >= -1 && choice < width, "periodic choice is outside its logical range")
			if choice >= 0 {
				current[voter] = choice
			}
			if current[voter] >= 0 {
				out[voter*width+current[voter]]++
			}
		}
	}

	return out
}

func countPeriodicSubmissions(choices [][]int) int {
	count := 0
	for _, periodChoices := range choices {
		for _, choice := range periodChoices {
			if choice >= 0 {
				count++
			}
		}
	}
	return count
}

// sumUint64 returns the total of v, panicking on overflow so a bad -qmax is
// caught here rather than as a silent wrap in the plaintext modulus choice.
func sumUint64(v []uint64) uint64 {
	var total uint64
	for _, x := range v {
		assert(total+x >= total, "sumUint64 overflow")
		total += x
	}
	return total
}

// weightedRowMaskSumPlain computes column sums of w * I(v > floor(T/2))
// on flattened n x b matrices (row-major layout).
func weightedRowMaskSumPlain(wFlat, vFlat []uint64, n, b, T int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")
	assert(T > 0, "T must be > 0")
	assert(len(wFlat) == n*b, "len(wFlat) must be n*b")
	assert(len(vFlat) == n*b, "len(vFlat) must be n*b")

	out := make([]uint64, b)
	threshold := uint64(T / 2)
	for i := 0; i < n; i++ {
		rowOffset := i * b
		for c := 0; c < b; c++ {
			value := vFlat[rowOffset+c]
			if value > threshold {
				out[c] += wFlat[rowOffset+c]
			}
		}
	}
	return out
}

func ceilDiv(n, d int) int {
	assert(n >= 0, "n must be >= 0")
	assert(d > 0, "d must be > 0")
	if n == 0 {
		return 0
	}
	return 1 + (n-1)/d
}

func modReduceSigned(v int64, modulus uint64) uint64 {
	assert(modulus > 0, "modulus must be > 0")
	vm := v % int64(modulus)
	if vm < 0 {
		vm += int64(modulus)
	}
	return uint64(vm)
}

func modAdd(a, b, modulus uint64) uint64 {
	assert(modulus > 0, "modulus must be > 0")
	return (a + b) % modulus
}

func modMul(a, b, modulus uint64) uint64 {
	assert(modulus > 0, "modulus must be > 0")
	return (a * b) % modulus
}

func modInverse(a, modulus uint64) uint64 {
	assert(modulus > 1, "modulus must be > 1")
	t, newT := int64(0), int64(1)
	r, newR := int64(modulus), int64(a%modulus)

	for newR != 0 {
		q := r / newR
		t, newT = newT, t-q*newT
		r, newR = newR, r-q*newR
	}

	assert(r == 1, "value is not invertible modulo modulus")
	if t < 0 {
		t += int64(modulus)
	}
	return uint64(t)
}

func lagrangeIndicatorCoefficients(T int, modulus uint64) []uint64 {
	assert(T >= 0, "T must be >= 0")
	assert(uint64(T) < modulus, "T must be smaller than plaintext modulus")

	coeffs := make([]uint64, T+1)
	threshold := T / 2

	for i := 0; i <= T; i++ {
		if i <= threshold {
			continue
		}

		basis := []uint64{1}
		denominator := uint64(1)

		for j := 0; j <= T; j++ {
			if j == i {
				continue
			}

			nextBasis := make([]uint64, len(basis)+1)
			negJ := modReduceSigned(-int64(j), modulus)
			for k, coeff := range basis {
				nextBasis[k] = modAdd(nextBasis[k], modMul(coeff, negJ, modulus), modulus)
				nextBasis[k+1] = modAdd(nextBasis[k+1], coeff, modulus)
			}
			basis = nextBasis

			denominator = modMul(denominator, modReduceSigned(int64(i-j), modulus), modulus)
		}

		scale := modInverse(denominator, modulus)
		for k, coeff := range basis {
			coeffs[k] = modAdd(coeffs[k], modMul(coeff, scale, modulus), modulus)
		}
	}

	return coeffs
}

type packingLayout struct {
	rowsPerCiphertext   int
	colsPerCiphertext   int
	votersPerRow        int
	votersPerCiphertext int
	totalRows           int
	ciphertextCount     int
}

func computePackingLayout(voterCount, candidateCount, rowsPerCiphertext, colsPerCiphertext int) packingLayout {
	assert(voterCount >= 0, "voterCount must be >= 0")
	assert(candidateCount > 0, "candidateCount must be > 0")
	assert(rowsPerCiphertext > 0, "rowsPerCiphertext must be > 0")
	assert(colsPerCiphertext > 0, "colsPerCiphertext must be > 0")

	votersPerRow := colsPerCiphertext / candidateCount
	assert(votersPerRow > 0, "candidateCount must fit at least one voter per row")

	totalRows := ceilDiv(voterCount, votersPerRow)
	return packingLayout{
		rowsPerCiphertext:   rowsPerCiphertext,
		colsPerCiphertext:   colsPerCiphertext,
		votersPerRow:        votersPerRow,
		votersPerCiphertext: rowsPerCiphertext * votersPerRow,
		totalRows:           totalRows,
		ciphertextCount:     ceilDiv(totalRows, rowsPerCiphertext),
	}
}

// drainOneHot removes one unit from a voter's row of `remaining` and returns
// the column it came from, or -1 if that row is already empty.
//
// `remaining` is a row-major voterCount x width tally: entry (voter, col) is
// how many of the T periods that voter spends on col, so each row sums to T.
// The protocol encrypts one choice per period rather than one tally per voter,
// so each period we drain a single unit and encrypt the resulting one-hot
// vector; after T periods the encryptions sum back to the original row. The
// sum does not depend on the order units are drained in, so we simply take the
// first non-empty column.
func drainOneHot(remaining []uint64, voter, width int) int {
	row := remaining[voter*width : (voter+1)*width]
	for col, left := range row {
		if left > 0 {
			row[col]--
			return col
		}
	}
	return -1
}
