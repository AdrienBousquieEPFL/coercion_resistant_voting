package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"log"

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

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func must1[T any](v T, err error) T {
	must(err)
	return v
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatal("assertion failed: ", msg)
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
