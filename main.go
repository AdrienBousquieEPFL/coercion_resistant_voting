package main

import (
	"flag"
	"fmt"
	"runtime/debug"

	bgvpoly "github.com/tuneinsight/lattigo/v6/circuits/bgv/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	fmt.Println("Running the voting algorithm with a distributed secret key\n")
	// 1. Initialization
	// Problem dimensions are configurable via CLI flags so the benchmark can
	// sweep them without recompiling. Defaults match the original hardcoded run.
	nFlag := flag.Int("n", 5, "number of voters")
	bFlag := flag.Int("b", 2, "number of candidates")
	kFlag := flag.Int("k", 2, "number of delegates")
	TFlag := flag.Int("T", 3, "number of periods (always odd)")
	NFlag := flag.Int("N", 3, "number of decryptors")
	flag.Parse()

	n := *nFlag
	b := *bFlag
	k := *kFlag
	T := *TFlag
	N := *NFlag
	//D := [][]uint64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 1, 0}}
	//w := []uint64{0, 0, 1, 0, 0, 9, 0, 0, 2, 0, 0, 5, 1, 0, 3, 1, 0, 8, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 6}
	//t := []uint64{2, 7, 1, 8, 7, 2, 8, 1, 6, 3, 2, 7, 3, 6, 1, 8, 6, 3, 5, 4}

	InitMetrics(runMeta{N: n, B: b, K: k, T: T})
	defer func() {
		if r := recover(); r != nil {
			RecordCrash(r, debug.Stack())
			// Best effort: flush whatever metrics we have. Wrap in its own
			// recover so a finalize panic doesn't mask the original crash.
			func() {
				defer func() { _ = recover() }()
				_ = FinalizeMetrics()
			}()
			panic(r) // re-raise so the runtime prints the trace and exits non-zero
		}
		must(FinalizeMetrics())
	}()

	phInit := StartPhase("1-init-random-inputs")
	D := randomDelegationMatrix(n, k)    // delegation matrix of size n x k, where D[i][j] is the delegate index for voter i and delegate j
	w := randomDelegationVector(n, k, T) // weight vector representing the voting power per voter
	t := randomVotingVector(n, b, T)     // voting vector packed as an n x b row-major vector
	RecordSized("D_matrix", n, int64(k)*8, "n rows of k uint64 (one-hot)")
	RecordSized("w_vector", 1, int64(n)*int64(k)*8, "flat n*k uint64")
	RecordSized("t_vector", 1, int64(n)*int64(b)*8, "flat n*b uint64")
	phInit.Stop()

	// 2. Parameters and Keys setup
	phSetup := StartPhase("2-bgv-setup")
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

		// Plaintext modulus t: smallest NTT-friendly prime >= n.
		PlaintextModulus: 65_537,

		// Secret and error distributions (optional; these are defaults).
		Xs: ring.Ternary{P: 2.0 / 3.0},
		Xe: ring.DiscreteGaussian{
			Sigma: rlwe.DefaultNoise,
			Bound: rlwe.DefaultNoiseBound,
		},
	}

	// Record the chosen BGV parameters into the run metadata (meta.json) so each
	// run is self-describing for correctness and security (lattice) analysis.
	SetBGVParams(paramsLiteral)

	// Build BGV crypto context.
	rlweLiteral := paramsLiteral.GetRLWEParametersLiteral()
	rlweLiteral.RingType = ring.Standard
	rlweParams := must1(rlwe.NewParametersFromLiteral(rlweLiteral))
	params := must1(bgv.NewParameters(rlweParams, paramsLiteral.PlaintextModulus))

	/****** COMMENTED OUT FOR MULTIPARY CASE ******/
	// kgen := bgv.NewKeyGenerator(params)
	// sk, pk := kgen.GenKeyPairNew()
	/******************************************/

	fmt.Println("Plaintext modulus =", params.PlaintextModulus())
	fmt.Println("Ring type =", params.RingType())
	fmt.Println("Slots =", params.MaxSlots())
	fmt.Println("Dimensions =", params.MaxDimensions())
	assert(uint64(n) <= params.PlaintextModulus(), "n must be <= plaintext modulus")

	/****** ADDED FOR MULTIPARY CASE ******/
	// Creates a PRNG that will be used to sample the common reference string (crs)
	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	check(err)

	// Generate some keys for the receiver (target party)
	kgen := rlwe.NewKeyGenerator(params)
	tsk, _ := kgen.GenKeyPairNew()

	// Create the N input parties and generate their secret keys
	P := genparties(params, N)

	// Step 1: Setup of the collective public key and relinearization key
	l.Printf("========= Collective Setup Phase =========")

	pk := execCKGProtocol(params, crs, P)  // generates the collective public key
	rlk := execRKGProtocol(params, crs, P) // generates the collective relinearization key

	// evk := rlwe.NewMemEvaluationKeySet(rlk) // creates the evaluation key from the relinearization key

	fmt.Println("Setup done (cloud: %s, party: %s)",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	cks, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{})

	/******************************************/

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)

	dims := params.MaxDimensions()
	blockSize := max(b, k)
	layout := computePackingLayout(n, blockSize, dims.Rows, dims.Cols)

	fmt.Println("nCiphertext =", layout.ciphertextCount)

	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               nil,   // nil => params.MaxLevelQ()
		LevelP:               nil,   // nil => params.MaxLevelP()
		BaseTwoDecomposition: nil,   // nil => default decomposition
		Compressed:           false, // true => smaller key, needs expansion before use
	}
	/****** COMMENTED OUT FOR MULTIPARY CASE ******/
	// rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	/******************************************/
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
	// gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	gks := execGKGProtocol(params, crs, P, galEls, evkParams) // MP GEN OF GKS
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)
	polyEval := bgvpoly.NewEvaluator(params, evaluator)
	phSetup.Stop()
	RecordRelinKey("rlk", rlk)
	RecordGaloisKeys("galois_keys", gks)
	RecordSized("galois_elements", len(galEls), 8, "uint64 indices fed to GenGaloisKeysNew")

	// 3. Homomorphic computation.
	// 3.1 - Aggregate all inputs
	// Simulate the protocol: ciphertexts start as encryptions of zero, and each
	// voter contributes one fresh encrypted one-hot input per period. After T
	// periods this reproduces the same packed t and w ciphertexts as a direct
	// encryption, but with realistic per-input noise growth.
	phEncrypt := StartPhase("3.1-encrypt-pack")

	zeroSlots := make([]uint64, params.MaxSlots())
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(zeroSlots, ptZero))

	// Initialize the vector to 0 and encrypt it
	tCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	wCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	for ctIdx := 0; ctIdx < layout.ciphertextCount; ctIdx++ {
		CountOp("EncryptNew")
		tCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptZero))
		CountOp("EncryptNew")
		wCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptZero))
	}

	tRemaining := append([]uint64(nil), t...)
	wRemaining := append([]uint64(nil), w...)
	slotBuf := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())

	for period := 0; period < T; period++ {
		for j := 0; j < n; j++ {
			ctIdx := j / layout.votersPerCiphertext
			localIdx := j % layout.votersPerCiphertext
			rowInCt := localIdx / layout.votersPerRow
			voterInRow := localIdx % layout.votersPerRow
			blockStart := rowInCt*layout.colsPerCiphertext + voterInRow*blockSize

			tOffset := -1
			for c := 0; c < b; c++ {
				if tRemaining[j*b+c] > 0 {
					tOffset = c
					break
				}
			}
			if tOffset >= 0 {
				tRemaining[j*b+tOffset]--
				slotBuf[blockStart+tOffset] = 1
			}
			CountOp("Encode")
			must(encoder.Encode(slotBuf, ptInput))
			CountOp("EncryptNew")
			ctT := must1(encryptor.EncryptNew(ptInput))
			CountOp("Add")
			must(evaluator.Add(tCiphertexts[ctIdx], ctT, tCiphertexts[ctIdx]))
			if tOffset >= 0 {
				slotBuf[blockStart+tOffset] = 0
			}

			wOffset := -1
			for c := 0; c < k; c++ {
				if wRemaining[j*k+c] > 0 {
					wOffset = c
					break
				}
			}
			if wOffset >= 0 {
				wRemaining[j*k+wOffset]--
				slotBuf[blockStart+wOffset] = 1
			}
			CountOp("Encode")
			must(encoder.Encode(slotBuf, ptInput))
			CountOp("EncryptNew")
			ctW := must1(encryptor.EncryptNew(ptInput))
			CountOp("Add")
			must(evaluator.Add(wCiphertexts[ctIdx], ctW, wCiphertexts[ctIdx]))
			if wOffset >= 0 {
				slotBuf[blockStart+wOffset] = 0
			}
		}
	}
	phEncrypt.Stop()
	RecordCiphertexts("tCiphertexts", tCiphertexts)
	RecordCiphertexts("wCiphertexts", wCiphertexts)

	// 3.2 - Lagrange interpolation I(x > T/2)
	decryptor := bgv.NewDecryptor(params, tsk) // CHANGED TO TSK FOR MULTIPARTY CASE
	phIndicator := StartPhase("3.2-lagrange-indicator")
	indicatorCoeffs := lagrangeIndicatorCoefficients(T, params.PlaintextModulus())
	indicatorDegree := len(indicatorCoeffs) - 1
	for i, ct := range tCiphertexts {
		CountOp("PolyEvaluate")
		CountPolyEvalOps(indicatorDegree)
		tCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
	}
	for i, ct := range wCiphertexts {
		CountOp("PolyEvaluate")
		CountPolyEvalOps(indicatorDegree)
		wCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
	}
	phIndicator.Stop()
	mp_verifyIndicatorCiphertexts("t after indicator", decryptor, encoder, params, layout, blockSize, b, t, tCiphertexts, T, &cks, P)
	mp_verifyIndicatorCiphertexts("w after indicator", decryptor, encoder, params, layout, blockSize, k, w, wCiphertexts, T, &cks, P)

	// 3.3 - Computing the delegating indicator vector
	phDTilde := StartPhase("3.3-dTilde")
	dTildeCiphertexts := make([]*rlwe.Ciphertext, len(wCiphertexts))
	for ctIdx, wCt := range wCiphertexts {
		ctRowSums := wCt.CopyNew()
		for shift := 1; shift < k; shift++ {
			CountOp("RotateColumnsNew")
			ctRot := must1(evaluator.RotateColumnsNew(wCt, shift))
			CountOp("Add")
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
		CountOp("Encode")
		must(encoder.Encode(mask, ptMask))

		CountOp("MulNew")
		ctBase := must1(evaluator.MulNew(ctRowSums, ptMask))
		CountOp("MulNew")
		ctNeg := must1(evaluator.MulNew(ctBase, -1))
		CountOp("AddNew")
		dTildeCiphertexts[ctIdx] = must1(evaluator.AddNew(ctNeg, ptMask))
	}
	phDTilde.Stop()
	RecordCiphertexts("dTildeCiphertexts", dTildeCiphertexts)
	mp_verifyBaseSlotCiphertexts("dTilde", decryptor, encoder, params, layout, blockSize, delegationIndicatorPlain(w, n, k, T), dTildeCiphertexts, &cks, P)

	// 3.4 - Aggregate row of w
	phSupport := StartPhase("3.4-delegate-support")
	assert(len(wCiphertexts) > 0, "wCiphertexts must be > 0")
	ctDelegateSupport := bgv.NewCiphertext(params, 1, wCiphertexts[0].Level())
	CountOp("RotateAndAdd")
	must(evaluator.RotateAndAdd(wCiphertexts[0], blockSize, layout.votersPerRow, ctDelegateSupport))
	CountOp("RotateRowsNew")
	ctRowSwapW := must1(evaluator.RotateRowsNew(ctDelegateSupport))
	CountOp("AddNew")
	ctDelegateSupport = must1(evaluator.AddNew(ctDelegateSupport, ctRowSwapW))
	for i := 1; i < len(wCiphertexts); i++ {
		ctPartial := bgv.NewCiphertext(params, 1, wCiphertexts[i].Level())
		CountOp("RotateAndAdd")
		must(evaluator.RotateAndAdd(wCiphertexts[i], blockSize, layout.votersPerRow, ctPartial))
		CountOp("RotateRowsNew")
		ctPartialRowSwap := must1(evaluator.RotateRowsNew(ctPartial))
		CountOp("AddNew")
		ctPartial = must1(evaluator.AddNew(ctPartial, ctPartialRowSwap))
		CountOp("Add")
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
	CountOp("Encode")
	must(encoder.Encode(delegateMask, ptDelegateMask))
	CountOp("MulNew")
	ctDelegateSupport = must1(evaluator.MulNew(ctDelegateSupport, ptDelegateMask))
	phSupport.Stop()
	RecordCiphertexts("ctDelegateSupport", []*rlwe.Ciphertext{ctDelegateSupport})
	mp_verifyLeadingSlotsCiphertext("delegate support", decryptor, encoder, params, delegateSupportPlain(w, n, k, T), ctDelegateSupport, &cks, P)

	// 3.5 - Compute the voter weights votWeights = Dw + dTilde
	// Precompute one-hot target mask plaintexts indexed by local voter position within a ciphertext.
	phDw := StartPhase("3.5-Dw+dTilde")
	targetMaskPts := make([]*rlwe.Plaintext, layout.votersPerCiphertext)
	for localVoterIdx := range layout.votersPerCiphertext {
		blockStart := (localVoterIdx / layout.votersPerRow) * layout.colsPerCiphertext
		blockStart += (localVoterIdx % layout.votersPerRow) * blockSize
		targetMask := make([]uint64, params.MaxSlots())
		targetMask[blockStart] = 1
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		CountOp("Encode")
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

				CountOp("RotateColumnsNew")
				ctRot := must1(evaluator.RotateColumnsNew(ctDelegateSupport, l-blockStart))
				CountOp("MulNew")
				ctTerm := must1(evaluator.MulNew(ctRot, targetMaskPts[localVoterIdx]))
				CountOp("Add")
				must(evaluator.Add(ctDw, ctTerm, ctDw))
			}
		}
		dwCiphertexts[ctIdx] = ctDw
		CountOp("AddNew")
		voterWeightCiphertexts[ctIdx] = must1(evaluator.AddNew(ctDw, dTildeCiphertexts[ctIdx]))
	}
	phDw.Stop()
	RecordCiphertexts("dwCiphertexts", dwCiphertexts)
	RecordCiphertexts("voterWeightCiphertexts", voterWeightCiphertexts)
	// Verification of Dw + dTilde
	expectedDw := make([]uint64, n)
	delegateSupport := delegateSupportPlain(w, n, k, T)
	for i := 0; i < n; i++ {
		for l := 0; l < k; l++ {
			expectedDw[i] += D[i][l] * delegateSupport[l]
		}
	}
	mp_verifyBaseSlotCiphertexts("encrypted D w_d", decryptor, encoder, params, layout, blockSize, expectedDw, dwCiphertexts, &cks, P)
	mp_verifyBaseSlotCiphertexts("Dw_d + dTilde", decryptor, encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, w, n, k, T), voterWeightCiphertexts, &cks, P)

	// 3.6 - Product of t and w
	phTally := StartPhase("3.6-tally")
	assert(layout.ciphertextCount > 0, "ciphertextCount must be > 0")
	voterWeightExpanded := make([]*rlwe.Ciphertext, len(voterWeightCiphertexts))
	for i, ct := range voterWeightCiphertexts {
		voterWeightExpanded[i] = ct.CopyNew()
		for shift := 1; shift < b; shift++ {
			CountOp("RotateColumnsNew")
			ctRot := must1(evaluator.RotateColumnsNew(ct, -shift))
			CountOp("Add")
			must(evaluator.Add(voterWeightExpanded[i], ctRot, voterWeightExpanded[i]))
		}
	}

	CountOp("MulRelinNew")
	ctAcc := must1(evaluator.MulRelinNew(voterWeightExpanded[0], tCiphertexts[0]))
	for i := 1; i < layout.ciphertextCount; i++ {
		CountOp("MulRelinNew")
		ctPart := must1(evaluator.MulRelinNew(voterWeightExpanded[i], tCiphertexts[i]))
		CountOp("Add")
		must(evaluator.Add(ctAcc, ctPart, ctAcc))
	}

	// For each candidate block, sum across all voters packed in the row.
	ctResultRows := ctAcc.CopyNew()
	CountOp("RotateAndAdd")
	must(evaluator.RotateAndAdd(ctAcc, blockSize, layout.votersPerRow, ctResultRows))

	// Duplicate totals from both BGV rows into the first row for easy readout.
	CountOp("RotateRowsNew")
	ctRowSwap := must1(evaluator.RotateRowsNew(ctResultRows))
	CountOp("AddNew")
	ctResult := must1(evaluator.AddNew(ctResultRows, ctRowSwap))
	phTally.Stop()
	RecordCiphertexts("voterWeightExpanded", voterWeightExpanded)
	RecordCiphertexts("ctResult", []*rlwe.Ciphertext{ctResult})

	// 4. Decrypt and verify against plaintext reference.
	phDecrypt := StartPhase("4-decrypt-final")
	CountOp("DecryptNew")
	ptResult := decryptor.DecryptNew(ctResult)
	decoded := make([]uint64, params.MaxSlots())
	CountOp("Decode")
	must(encoder.Decode(ptResult, decoded))
	phDecrypt.Stop()
	fmt.Println("decrypted final tally =", decoded[:b])
	mp_verifyLeadingSlotsCiphertext("final tally", decryptor, encoder, params, delegatedMaskedTallyPlain(D, w, t, n, b, k, T), ctResult, &cks, P)
}
