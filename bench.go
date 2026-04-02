//go:build bench
// +build bench

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
	encryptSummary := opSummary{name: "EncryptNew"}
	mulRelinSummary := opSummary{name: "MulRelinNew"}
	addSummary := opSummary{name: "Add"}
	rotateAndAddSummary := opSummary{name: "RotateAndAdd"}
	rotateRowsSummary := opSummary{name: "RotateRowsNew"}
	addNewSummary := opSummary{name: "AddNew"}
	decryptSummary := opSummary{name: "DecryptNew"}

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

		var tCiphertext *rlwe.Ciphertext
		encryptSummary.add(measureOperation("EncryptNew", func() {
			tCiphertext = must1(encryptor.EncryptNew(ptT))
		}))
		tCiphertexts[ctIdx] = tCiphertext

		var wCiphertext *rlwe.Ciphertext
		encryptSummary.add(measureOperation("EncryptNew", func() {
			wCiphertext = must1(encryptor.EncryptNew(ptW))
		}))
		wCiphertexts[ctIdx] = wCiphertext
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
	var ctAcc *rlwe.Ciphertext
	mulRelinSummary.add(measureOperation("MulRelinNew", func() {
		ctAcc = must1(evaluator.MulRelinNew(wCiphertexts[0], tCiphertexts[0]))
	}))
	for i := 1; i < layout.ciphertextCount; i++ {
		var ctPart *rlwe.Ciphertext
		mulRelinSummary.add(measureOperation("MulRelinNew", func() {
			ctPart = must1(evaluator.MulRelinNew(wCiphertexts[i], tCiphertexts[i]))
		}))
		addSummary.add(measureOperation("Add", func() {
			must(evaluator.Add(ctAcc, ctPart, ctAcc))
		}))
	}

	// For each candidate block, sum across all voters packed in the row.
	ctResultRows := ctAcc.CopyNew()
	rotateAndAddSummary.add(measureOperation("RotateAndAdd", func() {
		must(evaluator.RotateAndAdd(ctAcc, b, layout.votersPerRow, ctResultRows))
	}))

	// Duplicate totals from both BGV rows into the first row for easy readout.
	var ctRowSwap *rlwe.Ciphertext
	rotateRowsSummary.add(measureOperation("RotateRowsNew", func() {
		ctRowSwap = must1(evaluator.RotateRowsNew(ctResultRows))
	}))
	var ctResult *rlwe.Ciphertext
	addNewSummary.add(measureOperation("AddNew", func() {
		ctResult = must1(evaluator.AddNew(ctResultRows, ctRowSwap))
	}))

	// 4. Decrypt and verify against plaintext reference.
	decryptor := bgv.NewDecryptor(params, sk)
	var ptResult *rlwe.Plaintext
	decryptSummary.add(measureOperation("DecryptNew", func() {
		ptResult = decryptor.DecryptNew(ctResult)
	}))
	decoded := make([]uint64, params.MaxSlots())
	must(encoder.Decode(ptResult, decoded))

	finalTally := decoded[:b]
	opRows := []opSummary{
		encryptSummary,
		mulRelinSummary,
		addSummary,
		rotateAndAddSummary,
		rotateRowsSummary,
		addNewSummary,
		decryptSummary,
	}
	ctRows := []ciphertextSizeSummary{
		summarizeCiphertextSizes("tCiphertexts", tCiphertexts),
		summarizeCiphertextSizes("wCiphertexts", wCiphertexts),
		summarizeCiphertextSizes("ctAcc", []*rlwe.Ciphertext{ctAcc}),
		summarizeCiphertextSizes("ctResult", []*rlwe.Ciphertext{ctResult}),
	}

	fmt.Println("")
	fmt.Println("Results")
	fmt.Println("decrypted computed result =", finalTally)
	plainTotals := weightedRowSumPlain(w, t, n, b)
	fmt.Println("plain computed result =", plainTotals)
	for i := range b {
		assert(plainTotals[i] == finalTally[i], fmt.Sprintf("Mismatch at index %d: expected %d, got %d", i, plainTotals[i], finalTally[i]))
	}

	fmt.Println("")
	printCiphertextSizeTable(ctRows)
	fmt.Println("")
	printOperationMetricsTable(opRows)

	const metricsCSVPath = "metrics_latest.csv"
	must(writeMetricsCSV(metricsCSVPath, opRows, ctRows))
	fmt.Println("")
	fmt.Println("CSV metrics written to", metricsCSVPath)

}
