package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"log"
	"math/bits"
)

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

func powUint64(base uint64, exp int) uint64 {
	assert(exp >= 0, "exp must be >= 0")
	res := uint64(1)
	for i := 0; i < exp; i++ {
		assert(base == 0 || res <= ^uint64(0)/base, "powUint64 overflow")
		res *= base
	}
	return res
}


func innerProductUint64(w, v []uint64) uint64 {
	assert(len(w) == len(v), "innerProduct: len(w) must equal len(v)")

	var sum uint64
	for i := range w {
		hi, lo := bits.Mul64(w[i], v[i])
		assert(hi == 0, "innerProduct overflow in multiplication")
		var carry uint64
		sum, carry = bits.Add64(sum, lo, 0)
		assert(carry == 0, "innerProduct overflow in accumulation")
	}

	return sum
}

// randomWeightVector samples one weight per voter, then repeats each weight b times
// to obtain a flattened n x b row-major matrix.
func randomWeightVector(n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")

	w := make([]uint64, n)
	if n == 0 {
		return make([]uint64, 0)
	}

	upper := uint64(n)
	for k := 0; k < n; k++ {
		idx := randUint64n(upper)
		w[int(idx)]++
	}

	expanded := make([]uint64, n*b)
	pos := 0
	for i := 0; i < n; i++ {
		for j := 0; j < b; j++ {
			expanded[pos] = w[i]
			pos++
		}
	}

	return expanded
}

// randomVotingVector returns a flattened n x b row-major matrix with one random
// one-hot entry per row.
func randomVotingVector(n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")

	v := make([]uint64, n*b)
	for i := 0; i < n; i++ {
		col := int(randUint64n(uint64(b)))
		v[i*b+col] = 1
	}

	return v
}

// weightedRowSumPlain computes column sums of the element-wise product of two
// flattened n x b matrices (row-major layout).
func weightedRowSumPlain(wFlat, vFlat []uint64, n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")
	assert(len(wFlat) == n*b, "len(wFlat) must be n*b")
	assert(len(vFlat) == n*b, "len(vFlat) must be n*b")

	out := make([]uint64, b)
	for i := 0; i < n; i++ {
		rowOffset := i * b
		for c := 0; c < b; c++ {
			out[c] += wFlat[rowOffset+c] * vFlat[rowOffset+c]
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
