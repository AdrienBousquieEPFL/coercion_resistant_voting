package main

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// randomWeightVector returns a random integer vector w of length n such that:
// - each w[i] is in [0, n]
// - sum_i w[i] = n
// After finding this vector it transforms it in a n x b vector where we repeat b each element in this form
// (w1, w1, ..., w1, w2, w2, ..., w2, ..., wn, wn, ..., wn)
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

// randomVoting vector represents a n x b matrix in 1 vector where each row contains
// only one entry equal to 1 and this entry is random on every row
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

func main() {
	// 1. Initialization
	n := 65_536                  // number of voters
	b := 20                       // number of candidates
	w := randomWeightVector(n, b) // weight vector representing the voting power per voter
	v := randomVotingVector(n, b) // voting vector packed as an n x b row-major vector

	plainTotals := weightedRowSumPlain(w, v, n, b)

	// 2. Encryption
	// 2.1 Encryption parameters
	// Edit these values to experiment with BFV settings.
	// IMPORTANT: set either (Q, P) OR (LogQ, LogP), not both.
	paramsLiteral := bgv.ParametersLiteral{
		LogN: 14, // ring degree N = 2^LogN

		// Option A: let Lattigo generate NTT primes from bit-sizes.
		LogQ: []int{55, 45, 45, 45, 45, 45, 45, 45}, // ciphertext modulus chain
		LogP: []int{61},                             // special primes for key-switching/relin

		// Option B: provide explicit primes (uncomment and remove LogQ/LogP).
		// Q: []uint64{...},
		// P: []uint64{...},

		// Plaintext modulus t (must be non-zero, <= Q[0], and coprime with Q).
		PlaintextModulus: 0x10001,

		// Secret and error distributions (optional; these are defaults).
		Xs: ring.Ternary{P: 2.0 / 3.0},
		Xe: ring.DiscreteGaussian{
			Sigma: rlwe.DefaultNoise,
			Bound: rlwe.DefaultNoiseBound,
		},
	}

	// 2.2 Build BFV crypto context
	rlweLiteral := paramsLiteral.GetRLWEParametersLiteral()
	rlweLiteral.RingType = ring.Standard
	rlweParams := must1(rlwe.NewParametersFromLiteral(rlweLiteral))
	params := must1(bgv.NewParameters(rlweParams, paramsLiteral.PlaintextModulus))
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	fmt.Println("Plaintext modulus =", params.PlaintextModulus())
	fmt.Println("Ring type =", params.RingType())
	fmt.Println("Slots =", params.MaxSlots())
	fmt.Println("Dimensions =", params.MaxDimensions())

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)

	// Divide v in n_ciphetexts vector, each containing n_voters_per_ciphertext voters (except maybe the last one) and encrypt each of them separately
	nRowsPerCiphertext := params.MaxDimensions().Rows
	nColumnsPerCiphertext := params.MaxDimensions().Cols
	nVotersPerRow := int(math.Floor(float64(params.MaxDimensions().Cols) / float64(b)))
	nVotersPerCiphertext := nRowsPerCiphertext * nVotersPerRow
	nRows := int(math.Ceil(float64(n) / float64(nVotersPerRow)))
	nCiphertext := int(math.Ceil(float64(nRows) / float64(nRowsPerCiphertext)))

	fmt.Println("nCiphertext =", nCiphertext)

	vCiphertexts := make([]*rlwe.Ciphertext, nCiphertext)
	wCiphertexts := make([]*rlwe.Ciphertext, nCiphertext)
	for i := range nCiphertext {
		vContent := make([]uint64, params.MaxSlots())
		wContent := make([]uint64, params.MaxSlots())
		for j := range nRowsPerCiphertext {
			startCipher := j * nColumnsPerCiphertext
			endCipher := startCipher + nColumnsPerCiphertext
			start:= i * nVotersPerCiphertext * b + j * nVotersPerRow * b
			end := min(start + nVotersPerRow*b, len(v))
			if end < start {
				break
			}
			copy(vContent[startCipher:endCipher], v[start:end])
			copy(wContent[startCipher:endCipher], w[start:end])
		}
		ptV := bgv.NewPlaintext(params, params.MaxLevel())
		ptW := bgv.NewPlaintext(params, params.MaxLevel())
		must(encoder.Encode(vContent, ptV))
		must(encoder.Encode(wContent, ptW))
		vCiphertexts[i] = must1(encryptor.EncryptNew(ptV))
		wCiphertexts[i] = must1(encryptor.EncryptNew(ptW))
	}

	// Multiply w ciphertexts and v ciphertexts together
	// NOTE: We can add parameters to evaluation keys, scaleInvariant = true -> BFV
	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               nil,   // nil => params.MaxLevelQ()
		LevelP:               nil,   // nil => params.MaxLevelP()
		BaseTwoDecomposition: nil,   // nil => default decomposition
		Compressed:           false, // true => smaller key, needs expansion before use
	}
	rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	galEls := rlwe.GaloisElementsForInnerSum(params, b, nVotersPerRow)
	galEls = append(galEls, params.GaloisElementForRowRotation())
	gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)

	assert(nCiphertext > 0, "nCiphertext must be > 0")
	ctAcc := must1(evaluator.MulRelinNew(wCiphertexts[0], vCiphertexts[0]))
	for i := 1; i < nCiphertext; i++ {
		ctPart := must1(evaluator.MulRelinNew(wCiphertexts[i], vCiphertexts[i]))
		must(evaluator.Add(ctAcc, ctPart, ctAcc))
	}

	ctResult2Row := ctAcc.CopyNew()
	must(evaluator.RotateAndAdd(ctAcc, b, nVotersPerRow, ctResult2Row))

	ctSwap := must1(evaluator.RotateRowsNew(ctResult2Row))
	ctResult := must1(evaluator.AddNew(ctResult2Row, ctSwap))

	decryptor := bgv.NewDecryptor(params, sk)
	ptResult := decryptor.DecryptNew(ctResult)
	decodeResult := make([]uint64, params.MaxSlots())
	must(encoder.Decode(ptResult, decodeResult))

	fmt.Println("plain computed result =", plainTotals)
	fmt.Println("decrypted computed result =", decodeResult[:b])
	fmt.Println("decrypted computed result =", decodeResult[nColumnsPerCiphertext:b + nColumnsPerCiphertext])
	for i := 0; i < b; i++ {
		assert(plainTotals[i] == decodeResult[i], fmt.Sprintf("Mismatch at index %d: expected %d, got %d", i, plainTotals[i], decodeResult[i]))
	}

}

// TODO: Add the simulation of the mult. depth of vpacked and w after the precomputation of prior steps
