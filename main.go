package main

import (
	"fmt"

	bgvpoly "github.com/tuneinsight/lattigo/v6/circuits/bgv/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	// 1. Initialization
	n := 10_000 // number of voters
	b := 10     // number of candidates
	k := 100    // number of delegates
	T := 9      // number of periods (always odd)
	//D := [][]uint64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 1, 0}}
	//w := []uint64{0, 0, 1, 0, 0, 9, 0, 0, 2, 0, 0, 5, 1, 0, 3, 1, 0, 8, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 6}
	//t := []uint64{2, 7, 1, 8, 7, 2, 8, 1, 6, 3, 2, 7, 3, 6, 1, 8, 6, 3, 5, 4}
	D := randomDelegationMatrix(n, k)    // delegation matrix of size n x k, where D[i][j] is the delegate index for voter i and delegate j
	w := randomDelegationVector(n, k, T) // weight vector representing the voting power per voter
	t := randomVotingVector(n, b, T)     // voting vector packed as an n x b row-major vector

	// 2. BGV setup and encryption
	// Edit these values to experiment with BGV settings.
	// IMPORTANT: set either (Q, P) OR (LogQ, LogP), not both.
	LogN := 14
	paramsLiteral := bgv.ParametersLiteral{
		LogN: LogN, // ring degree N = 2^LogN

		// Option A: let Lattigo generate NTT primes from bit-sizes.
		LogQ: []int{55, 45, 45, 45, 45, 45, 45, 45}, // ciphertext modulus chain
		LogP: []int{61},                             // special primes for key-switching/relin

		// Option B: provide explicit primes (uncomment and remove LogQ/LogP).
		// Q: []uint64{...},
		// P: []uint64{...},

		// Plaintext modulus t: smallest NTT-friendly prime >= n.
		PlaintextModulus: pickPlaintextModulus(uint64(n), LogN),

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
	assert(uint64(n) <= params.PlaintextModulus(), "n must be <= plaintext modulus")

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)

	dims := params.MaxDimensions()
	blockSize := max(b, k)
	layout := computePackingLayout(n, blockSize, dims.Rows, dims.Cols)

	fmt.Println("nCiphertext =", layout.ciphertextCount)

	// Pack contiguous voters into ciphertexts. Each row stores up to votersPerRow
	// flattened voting rows; the last row/ciphertext may be partially filled.
	tCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	wCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	for ctIdx := 0; ctIdx < layout.ciphertextCount; ctIdx++ {
		tContent := make([]uint64, params.MaxSlots())
		wContent := make([]uint64, params.MaxSlots())

		for rowInCt := 0; rowInCt < layout.rowsPerCiphertext; rowInCt++ {
			rowBase := rowInCt * layout.colsPerCiphertext
			for voterInRow := 0; voterInRow < layout.votersPerRow; voterInRow++ {
				globalVoterIdx := ctIdx*layout.votersPerCiphertext + rowInCt*layout.votersPerRow + voterInRow
				if globalVoterIdx >= n {
					break
				}

				dstStart := rowBase + voterInRow*blockSize
				copy(tContent[dstStart:dstStart+b], t[globalVoterIdx*b:(globalVoterIdx+1)*b])
				copy(wContent[dstStart:dstStart+k], w[globalVoterIdx*k:(globalVoterIdx+1)*k])
			}
		}

		ptT := bgv.NewPlaintext(params, params.MaxLevel())
		ptW := bgv.NewPlaintext(params, params.MaxLevel())
		must(encoder.Encode(tContent, ptT))
		must(encoder.Encode(wContent, ptW))
		tCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptT))
		wCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptW))
	}

	// 3. Homomorphic computation.
	// 3.1 - Parameters
	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               nil,   // nil => params.MaxLevelQ()
		LevelP:               nil,   // nil => params.MaxLevelP()
		BaseTwoDecomposition: nil,   // nil => default decomposition
		Compressed:           false, // true => smaller key, needs expansion before use
	}
	rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	galEls := rlwe.GaloisElementsForInnerSum(params, b, layout.votersPerRow)
	galEls = append(galEls, rlwe.GaloisElementsForInnerSum(params, blockSize, layout.votersPerRow)...)
	for shift := 1; shift < k; shift++ {
		galEls = append(galEls, params.GaloisElementForColRotation(shift))
	}
	for shift := 1; shift < b; shift++ {
		galEls = append(galEls, params.GaloisElementForColRotation(-shift))
	}
	for globalVoterIdx := 0; globalVoterIdx < n; globalVoterIdx++ {
		localIdx := globalVoterIdx % layout.votersPerCiphertext
		rowInCt := localIdx / layout.votersPerRow
		voterInRow := localIdx % layout.votersPerRow
		targetSlot := rowInCt*layout.colsPerCiphertext + voterInRow*blockSize
		for l := 0; l < k; l++ {
			if D[globalVoterIdx][l] == 1 {
				galEls = append(galEls, params.GaloisElementForColRotation(l-targetSlot))
			}
		}
	}
	galEls = append(galEls, params.GaloisElementForRowRotation())
	gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)
	polyEval := bgvpoly.NewEvaluator(params, evaluator)

	// 3.2 - Lagrange interpolation I(x > T/2)
	decryptor := bgv.NewDecryptor(params, sk)
	indicatorCoeffs := lagrangeIndicatorCoefficients(T, params.PlaintextModulus())
	for i, ct := range tCiphertexts {
		tCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
	}
	for i, ct := range wCiphertexts {
		wCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
	}
	verifyIndicatorCiphertexts("t after indicator", decryptor, encoder, params, layout, blockSize, b, t, tCiphertexts, T)
	verifyIndicatorCiphertexts("w after indicator", decryptor, encoder, params, layout, blockSize, k, w, wCiphertexts, T)

	// 3.3 - Computing the delegating indicator vector
	dTildeCiphertexts := make([]*rlwe.Ciphertext, len(wCiphertexts))
	for ctIdx, wCt := range wCiphertexts {
		ctRowSums := wCt.CopyNew()
		for shift := 1; shift < k; shift++ {
			ctRot := must1(evaluator.RotateColumnsNew(wCt, shift))
			must(evaluator.Add(ctRowSums, ctRot, ctRowSums))
		}

		mask := make([]uint64, params.MaxSlots())
		votersInCt := min(layout.votersPerCiphertext, n-ctIdx*layout.votersPerCiphertext)
		for voterIdx := 0; voterIdx < votersInCt; voterIdx++ {
			slotIdx := (voterIdx / layout.votersPerRow) * layout.colsPerCiphertext
			slotIdx += (voterIdx % layout.votersPerRow) * blockSize
			mask[slotIdx] = 1
		}

		ptMask := bgv.NewPlaintext(params, params.MaxLevel())
		must(encoder.Encode(mask, ptMask))

		ctBase := must1(evaluator.MulNew(ctRowSums, ptMask))
		ctNeg := must1(evaluator.MulNew(ctBase, -1))
		dTildeCiphertexts[ctIdx] = must1(evaluator.AddNew(ctNeg, ptMask))
	}
	verifyBaseSlotCiphertexts("dTilde", decryptor, encoder, params, layout, blockSize, delegationIndicatorPlain(w, n, k, T), dTildeCiphertexts)

	// 3.4 - Aggregate row of w
	assert(len(wCiphertexts) > 0, "wCiphertexts must be > 0")
	ctDelegateSupport := bgv.NewCiphertext(params, 1, wCiphertexts[0].Level())
	must(evaluator.RotateAndAdd(wCiphertexts[0], blockSize, layout.votersPerRow, ctDelegateSupport))
	ctRowSwapW := must1(evaluator.RotateRowsNew(ctDelegateSupport))
	ctDelegateSupport = must1(evaluator.AddNew(ctDelegateSupport, ctRowSwapW))
	for i := 1; i < len(wCiphertexts); i++ {
		ctPartial := bgv.NewCiphertext(params, 1, wCiphertexts[i].Level())
		must(evaluator.RotateAndAdd(wCiphertexts[i], blockSize, layout.votersPerRow, ctPartial))
		ctPartialRowSwap := must1(evaluator.RotateRowsNew(ctPartial))
		ctPartial = must1(evaluator.AddNew(ctPartial, ctPartialRowSwap))
		must(evaluator.Add(ctDelegateSupport, ctPartial, ctDelegateSupport))
	}

	delegateMask := make([]uint64, params.MaxSlots())
	for row := 0; row < layout.rowsPerCiphertext; row++ {
		rowBase := row * layout.colsPerCiphertext
		for l := 0; l < k; l++ {
			delegateMask[rowBase+l] = 1
		}
	}
	ptDelegateMask := bgv.NewPlaintext(params, params.MaxLevel())
	must(encoder.Encode(delegateMask, ptDelegateMask))
	ctDelegateSupport = must1(evaluator.MulNew(ctDelegateSupport, ptDelegateMask))
	verifyLeadingSlotsCiphertext("delegate support", decryptor, encoder, params, delegateSupportPlain(w, n, k, T), ctDelegateSupport)

	// 3.5 - Compute the voter weights votWeights = Dw + dTilde
	// Precompute one-hot target mask plaintexts indexed by local voter position within a ciphertext.
	targetMaskPts := make([]*rlwe.Plaintext, layout.votersPerCiphertext)
	for localVoterIdx := range layout.votersPerCiphertext {
		blockStart := (localVoterIdx / layout.votersPerRow) * layout.colsPerCiphertext
		blockStart += (localVoterIdx % layout.votersPerRow) * blockSize
		targetMask := make([]uint64, params.MaxSlots())
		targetMask[blockStart] = 1
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		must(encoder.Encode(targetMask, pt))
		targetMaskPts[localVoterIdx] = pt
	}

	voterWeightCiphertexts := make([]*rlwe.Ciphertext, len(dTildeCiphertexts))
	dwCiphertexts := make([]*rlwe.Ciphertext, len(dTildeCiphertexts))
	for ctIdx := range voterWeightCiphertexts {
		votersInCt := min(layout.votersPerCiphertext, n-ctIdx*layout.votersPerCiphertext)
		ctDw := bgv.NewCiphertext(params, 1, ctDelegateSupport.Level())
		for localVoterIdx := 0; localVoterIdx < votersInCt; localVoterIdx++ {
			globalVoterIdx := ctIdx*layout.votersPerCiphertext + localVoterIdx
			blockStart := (localVoterIdx / layout.votersPerRow) * layout.colsPerCiphertext
			blockStart += (localVoterIdx % layout.votersPerRow) * blockSize

			for l := 0; l < k; l++ {
				if D[globalVoterIdx][l] == 0 {
					continue
				}

				ctRot := must1(evaluator.RotateColumnsNew(ctDelegateSupport, l-blockStart))
				ctTerm := must1(evaluator.MulNew(ctRot, targetMaskPts[localVoterIdx]))
				must(evaluator.Add(ctDw, ctTerm, ctDw))
			}
		}
		dwCiphertexts[ctIdx] = ctDw
		voterWeightCiphertexts[ctIdx] = must1(evaluator.AddNew(ctDw, dTildeCiphertexts[ctIdx]))
	}
	expectedDw := make([]uint64, n)
	delegateSupport := delegateSupportPlain(w, n, k, T)
	for i := 0; i < n; i++ {
		for l := 0; l < k; l++ {
			expectedDw[i] += D[i][l] * delegateSupport[l]
		}
	}
	verifyBaseSlotCiphertexts("encrypted D w_d", decryptor, encoder, params, layout, blockSize, expectedDw, dwCiphertexts)
	verifyBaseSlotCiphertexts("Dw_d + dTilde", decryptor, encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, w, n, k, T), voterWeightCiphertexts)

	// 3.6 - Product of t and w
	assert(layout.ciphertextCount > 0, "ciphertextCount must be > 0")
	voterWeightExpanded := make([]*rlwe.Ciphertext, len(voterWeightCiphertexts))
	for i, ct := range voterWeightCiphertexts {
		voterWeightExpanded[i] = ct.CopyNew()
		for shift := 1; shift < b; shift++ {
			ctRot := must1(evaluator.RotateColumnsNew(ct, -shift))
			must(evaluator.Add(voterWeightExpanded[i], ctRot, voterWeightExpanded[i]))
		}
	}

	ctAcc := must1(evaluator.MulRelinNew(voterWeightExpanded[0], tCiphertexts[0]))
	for i := 1; i < layout.ciphertextCount; i++ {
		ctPart := must1(evaluator.MulRelinNew(voterWeightExpanded[i], tCiphertexts[i]))
		must(evaluator.Add(ctAcc, ctPart, ctAcc))
	}

	// For each candidate block, sum across all voters packed in the row.
	ctResultRows := ctAcc.CopyNew()
	must(evaluator.RotateAndAdd(ctAcc, blockSize, layout.votersPerRow, ctResultRows))

	// Duplicate totals from both BGV rows into the first row for easy readout.
	ctRowSwap := must1(evaluator.RotateRowsNew(ctResultRows))
	ctResult := must1(evaluator.AddNew(ctResultRows, ctRowSwap))

	// 4. Decrypt and verify against plaintext reference.
	ptResult := decryptor.DecryptNew(ctResult)
	decoded := make([]uint64, params.MaxSlots())
	must(encoder.Decode(ptResult, decoded))
	fmt.Println("decrypted final tally =", decoded[:b])
	verifyLeadingSlotsCiphertext("final tally", decryptor, encoder, params, delegatedMaskedTallyPlain(D, w, t, n, b, k, T), ctResult)

}
