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
