package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	// 1. Initialization
	n := 65_536                   // number of voters
	b := 20                       // number of candidates
	w := randomWeightVector(n, b) // weight vector representing the voting power per voter
	t := randomVotingVector(n, b) // voting vector packed as an n x b row-major vector

	// 2. BGV setup and encryption
	// Edit these values to experiment with BGV settings.
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

	// Build BGV crypto context.
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

	dims := params.MaxDimensions()
	layout := computePackingLayout(n, b, dims.Rows, dims.Cols)

	fmt.Println("nCiphertext =", layout.ciphertextCount)

	// Pack contiguous voters into ciphertexts. Each row stores up to votersPerRow
	// flattened voting rows; the last row/ciphertext may be partially filled.
	tCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	wCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	for ctIdx := 0; ctIdx < layout.ciphertextCount; ctIdx++ {
		tContent := make([]uint64, params.MaxSlots())
		wContent := make([]uint64, params.MaxSlots())

		for rowInCt := 0; rowInCt < layout.rowsPerCiphertext; rowInCt++ {
			dstStart := rowInCt * layout.colsPerCiphertext
			srcStart := ctIdx*layout.votersPerCiphertext*b + rowInCt*layout.votersPerRow*b
			if srcStart >= len(t) {
				break
			}

			srcEnd := min(srcStart+layout.votersPerRow*b, len(t))
			copied := srcEnd - srcStart
			copy(tContent[dstStart:dstStart+copied], t[srcStart:srcEnd])
			copy(wContent[dstStart:dstStart+copied], w[srcStart:srcEnd])
		}

		ptT := bgv.NewPlaintext(params, params.MaxLevel())
		ptW := bgv.NewPlaintext(params, params.MaxLevel())
		must(encoder.Encode(tContent, ptT))
		must(encoder.Encode(wContent, ptW))
		tCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptT))
		wCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptW))
	}

	// 3. Homomorphic computation.
	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               nil,   // nil => params.MaxLevelQ()
		LevelP:               nil,   // nil => params.MaxLevelP()
		BaseTwoDecomposition: nil,   // nil => default decomposition
		Compressed:           false, // true => smaller key, needs expansion before use
	}
	rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	galEls := rlwe.GaloisElementsForInnerSum(params, b, layout.votersPerRow)
	galEls = append(galEls, params.GaloisElementForRowRotation())
	gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)

	assert(layout.ciphertextCount > 0, "ciphertextCount must be > 0")
	ctAcc := must1(evaluator.MulRelinNew(wCiphertexts[0], tCiphertexts[0]))
	for i := 1; i < layout.ciphertextCount; i++ {
		ctPart := must1(evaluator.MulRelinNew(wCiphertexts[i], tCiphertexts[i]))
		must(evaluator.Add(ctAcc, ctPart, ctAcc))
	}

	// For each candidate block, sum across all voters packed in the row.
	ctResultRows := ctAcc.CopyNew()
	must(evaluator.RotateAndAdd(ctAcc, b, layout.votersPerRow, ctResultRows))

	// Duplicate totals from both BGV rows into the first row for easy readout.
	ctRowSwap := must1(evaluator.RotateRowsNew(ctResultRows))
	ctResult := must1(evaluator.AddNew(ctResultRows, ctRowSwap))

	// 4. Decrypt and verify against plaintext reference.
	decryptor := bgv.NewDecryptor(params, sk)
	ptResult := decryptor.DecryptNew(ctResult)
	decoded := make([]uint64, params.MaxSlots())
	must(encoder.Decode(ptResult, decoded))

	finalTally := decoded[:b]
	fmt.Println("decrypted computed result =", finalTally)

	plainTotals := weightedRowSumPlain(w, t, n, b)
	fmt.Println("plain computed result =", plainTotals)
	for i := range b {
		assert(plainTotals[i] == finalTally[i], fmt.Sprintf("Mismatch at index %d: expected %d, got %d", i, plainTotals[i], finalTally[i]))
	}

}
