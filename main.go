package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// randomWeightVector returns a random integer vector w of length n such that:
// - each w[i] is in [0, n]
// - sum_i w[i] = n
func randomWeightVector(n int) []uint64 {
	assert(n >= 0, "n must be >= 0")

	w := make([]uint64, n)
	if n == 0 {
		return w
	}

	upper := uint64(n)
	for k := 0; k < n; k++ {
		idx := randUint64n(upper)
		w[int(idx)]++
	}

	return w
}

// randomVPackedVector returns a vector v of length N where each slot is B^a
// and a is sampled uniformly at random from [0, b).
func randomVPackedVector(N, b, B int) []uint64 {
	assert(N >= 0, "N must be >= 0")
	assert(b > 0, "b must be > 0")
	assert(B >= 0, "B must be >= 0")

	v := make([]uint64, N)

	for i := 0; i < N; i++ {
		a := int(randUint64n(uint64(b)))
		v[i] = powUint64(uint64(B), a)
	}

	return v
}


// extractBaseDigits returns exactly numDigits digits in base B, least-significant first.
// Returned digits correspond to coefficients of [B^0, B^1, ..., B^(numDigits-1)].
func extractBaseDigits(x uint64, B, numDigits int) []uint64 {
	assert(B >= 2, "B must be >= 2")
	assert(numDigits >= 0, "numDigits must be >= 0")

	digits := make([]uint64, numDigits)
	base := uint64(B)
	n := x
	for i := 0; i < numDigits; i++ {
		digits[i] = n % base
		n /= base
	}

	return digits
}

func main() {
	// 1. Initialization
	n := 5 // number of voters
	b := 2 // number of candidates
	B := n + 1
	w := randomWeightVector(n)                   // weight vector representing the voting power per voter
	vPacked := randomVPackedVector(n, b, B)      // the voting vector representing each vote in base B
	innerPlain := innerProductUint64(w, vPacked) // the final tally representation done in plain

	fmt.Println("w =", w)
	fmt.Println("vPacked =", vPacked)
	fmt.Println("plain inner(w, vPacked) =", innerPlain)

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
	params := must1(bgv.NewParametersFromLiteral(paramsLiteral))
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	// Evaluation key parameters are tunable as well.
	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               nil,   // nil => params.MaxLevelQ()
		LevelP:               nil,   // nil => params.MaxLevelP()
		BaseTwoDecomposition: nil,   // nil => default decomposition
		Compressed:           false, // true => smaller key, needs expansion before use
	}
	rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	galEls := params.GaloisElementsForInnerSum(1, n)
	gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)
	decryptor := bgv.NewDecryptor(params, sk)
	// BFV mode in Lattigo is BGV evaluator with scaleInvariant=true.
	evaluator := bgv.NewEvaluator(params, evk, true)

	// 3. Homomorphic inner product <w, vPacked>
	// TODO: Add the simulation of the mult. depth of vpacked and w after the precomputation of prior steps
	assert(n <= params.MaxSlots(), "n must be <= params.MaxSlots()")

	ptW := bgv.NewPlaintext(params, params.MaxLevel())
	ptV := bgv.NewPlaintext(params, params.MaxLevel())
	must(encoder.Encode(w, ptW))
	must(encoder.Encode(vPacked, ptV))

	ctW := must1(encryptor.EncryptNew(ptW))
	ctV := must1(encryptor.EncryptNew(ptV))

	// Slot-wise multiplication.
	ctMul := must1(evaluator.MulRelinNew(ctW, ctV))

	// Sum first n slots into slot 0.
	ctInner := ctMul.CopyNew()
	must(evaluator.RotateAndAdd(ctMul, 1, n, ctInner))

	ptInner := decryptor.DecryptNew(ctInner)
	decoded := make([]uint64, params.MaxSlots())
	must(encoder.Decode(ptInner, decoded))
	innerHE := decoded[0]

	innerPlainModT := innerPlain % params.PlaintextModulus()

	decodedPlainDigits := extractBaseDigits(innerPlainModT, B, b)
	decodedHEDigits := extractBaseDigits(innerHE, B, b)

	fmt.Println("plain inner mod t =", innerPlainModT)
	fmt.Println("HE inner (slot 0) =", innerHE)
	assert(innerHE == innerPlainModT, "HE inner product mismatch")
	fmt.Println("decoded tally from plain inner =", decodedPlainDigits)
	fmt.Println("decoded tally from HE inner =", decodedHEDigits)
}
