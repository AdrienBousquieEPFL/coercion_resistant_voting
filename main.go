package main

import (
	"flag"
	"fmt"
	"runtime/debug"

	bgvpoly "github.com/tuneinsight/lattigo/v6/circuits/bgv/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	// 1.1 - Election size parameters
	// Example: --n 100 --k 10 --b 4 --T 9 --qmax 8 --progress false
	nFlag := flag.Int("n", 100, "number of voters")
	bFlag := flag.Int("b", 5, "number of candidates")
	kFlag := flag.Int("k", 5, "number of delegates")
	TFlag := flag.Int("T", 5, "number of periods (always odd)")
	qMaxFlag := flag.Int("qmax", 1, "max initial voting power per voter; each q_i is drawn from [1, qmax]")
	progressFlag := flag.Bool("progress", true, "show progress on stderr")
	flag.Parse()

	n := *nFlag
	b := *bFlag
	k := *kFlag
	T := *TFlag
	qMax := *qMaxFlag
	progressEnabled = *progressFlag
	//D := [][]uint64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 1, 0}}
	//d := []uint64{0, 0, 1, 0, 0, 9, 0, 0, 2, 0, 0, 5, 1, 0, 3, 1, 0, 8, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 6}
	//v := []uint64{2, 7, 1, 8, 7, 2, 8, 1, 6, 3, 2, 7, 3, 6, 1, 8, 6, 3, 5, 4}

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

	// 1.2 - Random user input
	phInit := StartPhase("1-init-random-inputs")
	D := randomDelegationMatrix(n, k)    // delegation matrix of size n x k, where D[i][j] is the delegate index for voter i and delegate j
	d := randomDelegationVector(n, k, T) // delegation vector packed as a n x k row-major vector
	v := randomVotingVector(n, b, T)     // voting vector packed as a n x b row-major vector
	q := randomVotingPower(n, qMax)      // per-voter voting power q_i, one entry per voter
	// fmt.Println("D=", D)
	// fmt.Println("d=", d)
	// fmt.Println("v=", v)
	// fmt.Println("q=", q)
	RecordSized("D_matrix", n, int64(k)*8, "n rows of k uint64 (one-hot)")
	RecordSized("d_vector", 1, int64(n)*int64(k)*8, "flat n*k uint64")
	RecordSized("t_vector", 1, int64(n)*int64(b)*8, "flat n*b uint64")
	RecordSized("q_vector", 1, int64(n)*8, "flat n uint64 voting power")
	phInit.Stop()

	// 2. Parameters and Keys setup
	phSetup := StartPhase("2-bgv-setup")
	// Every per-delegate weighted total is bounded by the total voting power in
	// circulation, so t is picked as the smallest NTT-friendly prime strictly
	// above sum(q). With qMax=1 this is sum(q)=n, matching the previous bound.
	qSum := sumUint64(q)

	// Edit these values to experiment with BGV settings.
	// IMPORTANT: set either (Q, P) OR (LogQ, LogP), not both.
	const logN = 14
	paramsLiteral := bgv.ParametersLiteral{
		LogN: logN, // ring degree N = 2^LogN

		// Option A: let Lattigo generate NTT primes from bit-sizes.
		LogQ: []int{55, 45, 45, 45, 45, 45, 45, 45}, // ciphertext modulus chain
		LogP: []int{61},                             // special primes for key-switching/relin

		// Option B: provide explicit primes (uncomment and remove LogQ/LogP).
		// Q: []uint64{...},
		// P: []uint64{...},

		// Plaintext modulus t: smallest NTT-friendly prime > sum(q).
		PlaintextModulus: pickPlaintextModulus(qSum+1, logN),

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
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	fmt.Println("Plaintext modulus =", params.PlaintextModulus())
	fmt.Println("Ring type =", params.RingType())
	fmt.Println("Slots =", params.MaxSlots())
	fmt.Println("Dimensions =", params.MaxDimensions())
	fmt.Println("Total voting power sum(q) =", qSum)
	assert(qSum < params.PlaintextModulus(),
		fmt.Sprintf("sum(q)=%d must be < plaintext modulus t=%d", qSum, params.PlaintextModulus()))

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
	spinSetup := NewSpinner("2-bgv-setup: generating relinearization + Galois keys")
	rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	galEls := rlwe.GaloisElementsForInnerSum(params, b, layout.votersPerRow)
	galEls = append(galEls, rlwe.GaloisElementsForInnerSum(params, blockSize, layout.votersPerRow)...)
	// Inner-sum keys for the log-depth reduction of each voter's k delegation slots
	// in 3.4-dTilde (RotateAndAdd(wCt, 1, k)). This replaces a linear scan of k-1
	// column rotations, so the individual shift-1..k-1 rotation keys are no longer
	// generated here.
	galEls = append(galEls, rlwe.GaloisElementsForInnerSum(params, 1, k)...)
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
	spinSetup.Finish()
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)
	polyEval := bgvpoly.NewEvaluator(params, evaluator)
	phSetup.Stop()
	RecordRelinKey("rlk", rlk)
	RecordGaloisKeys("galois_keys", gks)
	RecordSized("galois_elements", len(galEls), 8, "uint64 indices fed to GenGaloisKeysNew")

	// 3. Homomorphic computation.
	// 3.1 - Aggregate all inputs
	// Here we simulate an input d and v without the mask z (as we consider all votes have been done correctly and there is no echo mechanism here)
	// TODO: Add the echo mechanism simulation
	phEncrypt := StartPhase("3.1-encrypt-pack")

	zeroSlots := make([]uint64, params.MaxSlots())
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(zeroSlots, ptZero))

	// Initialize the vector to 0 and encrypt it
	vCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	dCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	for ctIdx := 0; ctIdx < layout.ciphertextCount; ctIdx++ {
		CountOp("EncryptNew")
		vCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptZero))
		CountOp("EncryptNew")
		dCiphertexts[ctIdx] = must1(encryptor.EncryptNew(ptZero))
	}

	vRemaining := append([]uint64(nil), v...)
	dRemaining := append([]uint64(nil), d...)

	// Every voter casts one vote and one delegation per period, so this loop
	// performs 2*T*n independent fresh encryptions and folds each one into the
	// running Enc(0) accumulator for its ciphertext.
	// A multi-threaded variant of this phase is kept in 3.1-multithreaded.diff.
	slotBuf := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())
	encProg := NewProgress("3.1-encrypt-pack", int64(2)*int64(T)*int64(n))

	// accumulate encrypts the current slotBuf and adds it into dst[ctIdx].
	accumulate := func(dst []*rlwe.Ciphertext, ctIdx int) {
		CountOp("Encode")
		must(encoder.Encode(slotBuf, ptInput))
		CountOp("EncryptNew")
		ct := must1(encryptor.EncryptNew(ptInput))
		CountOp("Add")
		must(evaluator.Add(dst[ctIdx], ct, dst[ctIdx]))
		encProg.Inc()
	}

	for j := 0; j < n; j++ {
		ctIdx := j / layout.votersPerCiphertext
		localIdx := j % layout.votersPerCiphertext
		rowInCt := localIdx / layout.votersPerRow
		voterInRow := localIdx % layout.votersPerRow
		blockStart := rowInCt*layout.colsPerCiphertext + voterInRow*blockSize

		for period := 0; period < T; period++ {
			// slotBuf is kept all-zero between calls, so only the single hot
			// slot of this period's one-hot vector is ever set.
			vOffset := drainOneHot(vRemaining, j, b)
			if vOffset >= 0 {
				slotBuf[blockStart+vOffset] = 1
			}
			accumulate(vCiphertexts, ctIdx)
			if vOffset >= 0 {
				slotBuf[blockStart+vOffset] = 0
			}

			dOffset := drainOneHot(dRemaining, j, k)
			if dOffset >= 0 {
				slotBuf[blockStart+dOffset] = 1
			}
			accumulate(dCiphertexts, ctIdx)
			if dOffset >= 0 {
				slotBuf[blockStart+dOffset] = 0
			}
		}
	}
	encProg.Finish()
	phEncrypt.Stop()
	RecordCiphertexts("vCiphertexts", vCiphertexts)
	RecordCiphertexts("dCiphertexts", dCiphertexts)

	// 3.2 - Lagrange interpolation I(x > T/2)
	decryptor := bgv.NewDecryptor(params, sk)
	phIndicator := StartPhase("3.2-lagrange-indicator")
	indicatorCoeffs := lagrangeIndicatorCoefficients(T, params.PlaintextModulus())
	indicatorDegree := len(indicatorCoeffs) - 1
	indicatorProg := NewProgress("3.2-lagrange-indicator", int64(len(vCiphertexts)+len(dCiphertexts)))
	for i, ct := range vCiphertexts {
		CountOp("PolyEvaluate")
		CountPolyEvalOps(indicatorDegree)
		vCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
		indicatorProg.Inc()
	}
	for i, ct := range dCiphertexts {
		CountOp("PolyEvaluate")
		CountPolyEvalOps(indicatorDegree)
		dCiphertexts[i] = must1(polyEval.Evaluate(ct, bgvpoly.NewPolynomial(indicatorCoeffs), params.DefaultScale()))
		indicatorProg.Inc()
	}
	indicatorProg.Finish()
	phIndicator.Stop()
	verifyIndicatorCiphertexts("t after indicator", decryptor, encoder, params, layout, blockSize, b, v, vCiphertexts, T)
	verifyIndicatorCiphertexts("d after indicator", decryptor, encoder, params, layout, blockSize, k, d, dCiphertexts, T)

	// 3.3 - Aggregate row of d
	phSupport := StartPhase("3.3-delegate-support")
	assert(len(dCiphertexts) > 0, "dCiphertexts must be > 0")

	// q_ext replicates each voter's power q_i across the k delegation slots of
	// their block, so the slot-wise product d' * q_ext weights every delegation
	// choice by the power of the voter casting it. q is public, so this is a
	// plaintext-ciphertext product: it scales noise but consumes no level.
	qExtPts := make([]*rlwe.Plaintext, layout.ciphertextCount)
	for ctIdx := range qExtPts {
		slots := make([]uint64, params.MaxSlots())
		votersInCt := min(layout.votersPerCiphertext, n-ctIdx*layout.votersPerCiphertext)
		for localVoterIdx := 0; localVoterIdx < votersInCt; localVoterIdx++ {
			blockStart := (localVoterIdx / layout.votersPerRow) * layout.colsPerCiphertext
			blockStart += (localVoterIdx % layout.votersPerRow) * blockSize
			power := q[ctIdx*layout.votersPerCiphertext+localVoterIdx]
			for l := 0; l < k; l++ {
				slots[blockStart+l] = power
			}
		}
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		CountOp("Encode")
		must(encoder.Encode(slots, pt))
		qExtPts[ctIdx] = pt
	}

	dWeighted := make([]*rlwe.Ciphertext, len(dCiphertexts))
	for ctIdx, ct := range dCiphertexts {
		CountOp("MulNew")
		dWeighted[ctIdx] = must1(evaluator.MulNew(ct, qExtPts[ctIdx]))
	}

	ctDelegateSupport := bgv.NewCiphertext(params, 1, dWeighted[0].Level())
	CountOp("RotateAndAdd")
	must(evaluator.RotateAndAdd(dWeighted[0], blockSize, layout.votersPerRow, ctDelegateSupport))
	CountOp("RotateRowsNew")
	ctRowSwapW := must1(evaluator.RotateRowsNew(ctDelegateSupport))
	CountOp("AddNew")
	ctDelegateSupport = must1(evaluator.AddNew(ctDelegateSupport, ctRowSwapW))
	for i := 1; i < len(dWeighted); i++ {
		ctPartial := bgv.NewCiphertext(params, 1, dWeighted[i].Level())
		CountOp("RotateAndAdd")
		must(evaluator.RotateAndAdd(dWeighted[i], blockSize, layout.votersPerRow, ctPartial))
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
	RecordCiphertexts("dWeighted", dWeighted)
	RecordCiphertexts("ctDelegateSupport", []*rlwe.Ciphertext{ctDelegateSupport})
	verifyLeadingSlotsCiphertext("delegate support", decryptor, encoder, params, delegateSupportPlain(d, q, n, k, T), ctDelegateSupport)

	// 3.4 - Computing the weighted self-power vector dTilde * q
	phDTilde := StartPhase("3.4-dTilde")
	dTildeCiphertexts := make([]*rlwe.Ciphertext, len(dCiphertexts))
	for ctIdx, wCt := range dCiphertexts {
		// Sum each voter's k delegation slots into their block's base slot with a
		// logarithmic-depth inner sum (ceil(log2 k) rotations) instead of a linear
		// scan of k-1 rotations. RotateAndAdd(wCt, 1, k) sets slot i to the sum of
		// slots i..i+k-1, so every voter's base slot holds its k-slot delegation
		// total; the mask below keeps only those base slots. Relies on the
		// InnerSum(1, k) Galois keys generated in the setup phase.
		//
		// Majority selection leaves at most one nonzero slot per block, so each
		// inner sum is 0 or 1 and dTilde = 1 - sum is boolean. The mask carries
		// q_i rather than 1, so the same two multiplications that build 1 - sum
		// build q_i - q_i*sum = q_i * dTilde_i: a self-delegating voter keeps
		// their own power, a delegating voter drops to 0. No extra operation.
		ctRowSums := bgv.NewCiphertext(params, 1, wCt.Level())
		CountOp("RotateAndAdd")
		must(evaluator.RotateAndAdd(wCt, 1, k, ctRowSums))

		mask := make([]uint64, params.MaxSlots())
		votersInCt := min(layout.votersPerCiphertext, n-ctIdx*layout.votersPerCiphertext)
		for voterIdx := 0; voterIdx < votersInCt; voterIdx++ {
			slotIdx := (voterIdx / layout.votersPerRow) * layout.colsPerCiphertext
			slotIdx += (voterIdx % layout.votersPerRow) * blockSize
			mask[slotIdx] = q[ctIdx*layout.votersPerCiphertext+voterIdx]
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
	verifyBaseSlotCiphertexts("dTilde", decryptor, encoder, params, layout, blockSize, weightedSelfPowerPlain(d, q, n, k, T), dTildeCiphertexts)

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
	delegateSupport := delegateSupportPlain(d, q, n, k, T)
	for i := 0; i < n; i++ {
		for l := 0; l < k; l++ {
			expectedDw[i] += D[i][l] * delegateSupport[l]
		}
	}
	verifyBaseSlotCiphertexts("encrypted D w_d", decryptor, encoder, params, layout, blockSize, expectedDw, dwCiphertexts)
	verifyBaseSlotCiphertexts("Dw_d + dTilde", decryptor, encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, d, q, n, k, T), voterWeightCiphertexts)

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
	ctAcc := must1(evaluator.MulRelinNew(voterWeightExpanded[0], vCiphertexts[0]))
	for i := 1; i < layout.ciphertextCount; i++ {
		CountOp("MulRelinNew")
		ctPart := must1(evaluator.MulRelinNew(voterWeightExpanded[i], vCiphertexts[i]))
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
	verifyLeadingSlotsCiphertext("final tally", decryptor, encoder, params, delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T), ctResult)
}
