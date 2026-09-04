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
	// 1.1 - Election size parameters
	// Example: --n 100 --k 10 --b 4 --T 9 --qmax 8 --progress false
	nFlag := flag.Int("n", 100, "number of voters")
	bFlag := flag.Int("b", 5, "number of candidates")
	kFlag := flag.Int("k", 5, "number of delegates")
	TFlag := flag.Int("T", 5, "number of periods (always odd)")
	qMaxFlag := flag.Int("qmax", 1, "max initial voting power per voter; each q_i is drawn from [1, qmax]")
	progressFlag := flag.Bool("progress", true, "show progress on stderr")
	NFlag := flag.Int("N", 3, "number of decryptors")
	echoModeFlag := flag.String("echo-mode", "tree", "periodic echo evaluation: tree or sequential")
	echoRefreshIntervalFlag := flag.Int("echo-refresh-interval", 1, "sequential echo transitions between collective refreshes")
	flag.Parse()

	n := *nFlag
	b := *bFlag
	k := *kFlag
	T := *TFlag
	qMax := *qMaxFlag
	progressEnabled = *progressFlag
	N := *NFlag
	echoMode := *echoModeFlag
	echoRefreshInterval := *echoRefreshIntervalFlag
	assert(echoMode == "tree" || echoMode == "sequential", "echo-mode must be tree or sequential")
	assert(echoRefreshInterval > 0, "echo-refresh-interval must be > 0")
	if echoMode == "tree" {
		// The interval controls only intermediate refreshes in sequential mode.
		echoRefreshInterval = 0
	}
	//D := [][]uint64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 1, 0}}
	//d := []uint64{0, 0, 1, 0, 0, 9, 0, 0, 2, 0, 0, 5, 1, 0, 3, 1, 0, 8, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 6}
	//v := []uint64{2, 7, 1, 8, 7, 2, 8, 1, 6, 3, 2, 7, 3, 6, 1, 8, 6, 3, 5, 4}

	InitMetrics(runMeta{
		N:                   n,
		B:                   b,
		K:                   k,
		T:                   T,
		EchoMode:            echoMode,
		EchoRefreshInterval: echoRefreshInterval,
	})
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
	D := randomDelegationMatrix(n, k) // delegation matrix of size n x k, where D[i][j] is the delegate index for voter i and delegate j

	// Retain explicit period schedules so the encrypted tally and plaintext
	// reference can both model periods with no new submission. The initial count
	// vectors are only simulation seeds for generating those schedules.
	candidatePeriods := periodicChoicesFromCounts(randomVotingVector(n, b, T), n, b, T)
	delegationPeriods := periodicChoicesFromCounts(randomDelegationVector(n, k, T), n, k, T)
	ensureEchoCarryEvent(candidatePeriods)
	ensureEchoCarryEvent(delegationPeriods)

	// v and d are the effective totals after applying the periodic echo rule.
	// They are plaintext references only and are never operands in the tally.
	v := periodicEchoTotalsPlain(candidatePeriods, n, b)
	d := periodicEchoTotalsPlain(delegationPeriods, n, k)
	q := randomVotingPower(n, qMax) // per-voter voting power q_i, one entry per voter
	// fmt.Println("D=", D)
	// fmt.Println("d=", d)
	// fmt.Println("v=", v)
	// fmt.Println("q=", q)
	RecordSized("D_matrix", n, int64(k)*8, "n rows of k uint64 (one-hot)")
	RecordSized("delegation_periods", T, int64(n)*8, "period-major choice indices; -1 means no submission")
	RecordSized("candidate_periods", T, int64(n)*8, "period-major choice indices; -1 means no submission")
	RecordSized("d_vector", 1, int64(n)*int64(k)*8, "flat n*k uint64 after plaintext echo simulation")
	RecordSized("t_vector", 1, int64(n)*int64(b)*8, "flat n*b uint64 after plaintext echo simulation")
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

	/****** COMMENTED OUT FOR MULTIPARY CASE ******/
	// kgen := bgv.NewKeyGenerator(params)
	// sk, pk := kgen.GenKeyPairNew()
	/******************************************/

	fmt.Println("Plaintext modulus =", params.PlaintextModulus())
	fmt.Println("Ring type =", params.RingType())
	fmt.Println("Slots =", params.MaxSlots())
	fmt.Println("Dimensions =", params.MaxDimensions())
	fmt.Println("Total voting power sum(q) =", qSum)
	fmt.Println("Echo mode =", echoMode, "sequential refresh interval =", echoRefreshInterval)
	assert(qSum < params.PlaintextModulus(),
		fmt.Sprintf("sum(q)=%d must be < plaintext modulus t=%d", qSum, params.PlaintextModulus()))

	/****** ADDED FOR MULTIPARY CASE ******/
	// Creates a PRNG that will be used to sample the common reference string (crs)
	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	check(err)

	// Generate some keys for the receiver (target party)
	// kgen := rlwe.NewKeyGenerator(params)
	// tsk, _ := kgen.GenKeyPairNew()

	// Create the N input parties and generate their secret keys
	P := genparties(params, N)

	// Step 1: Setup of the collective public key and relinearization key
	l.Printf("========= Collective Setup Phase =========")

	pk := execCKGProtocol(params, crs, P)  // generates the collective public key
	rlk := execRKGProtocol(params, crs, P) // generates the collective relinearization key

	// evk := rlwe.NewMemEvaluationKeySet(rlk) // creates the evaluation key from the relinearization key

	fmt.Printf("Setup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	cks, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{})
	must(err)

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
	spinSetup := NewSpinner("2-bgv-setup: generating relinearization + Galois keys")
	/****** COMMENTED OUT FOR MULTIPARY CASE ******/
	// rlk := kgen.GenRelinearizationKeyNew(sk, evkParams)
	/******************************************/
	galEls := rlwe.GaloisElementsForInnerSum(params, b, layout.votersPerRow)
	galEls = append(galEls, rlwe.GaloisElementsForInnerSum(params, blockSize, layout.votersPerRow)...)
	// Inner-sum keys for the log-depth reduction of each voter's k delegation slots
	// in 4.5-dTilde (RotateAndAdd(wCt, 1, k)). This replaces a linear scan of k-1
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
	// gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)
	gks := execGKGProtocol(params, crs, P, galEls, evkParams) // MP GEN OF GKS
	spinSetup.Finish()
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	evaluator := bgv.NewEvaluator(params, evk, true)
	polyEval := bgvpoly.NewEvaluator(params, evaluator)
	phSetup.Stop()
	RecordRelinKey("rlk", rlk)
	RecordGaloisKeys("galois_keys", gks)
	RecordSized("galois_elements", len(galEls), 8, "uint64 indices fed to GenGaloisKeysNew")

	// 3. Pre-election input preparation.
	//
	// q is available here only because this executable locally simulates the
	// party that prepares the encrypted weight input and later uses q for
	// plaintext correctness checks. The tally begins below with qExtCiphertexts
	// and qBaseCiphertexts already encrypted under the collective public key.
	phWeights := StartPhase("3-pre-election-weight-input-preparation")

	// q_ext replicates each voter's power q_i across the k delegation slots of
	// their block. It is encrypted once per packed ciphertext under the
	// collective public key. qBaseCiphertexts is then derived from that same
	// encryption with a public structural mask, so the two encrypted layouts are
	// bound to the same weight input without a second encryption.
	baseSlotMask := make([]uint64, params.MaxSlots())
	for row := 0; row < layout.rowsPerCiphertext; row++ {
		rowBase := row * layout.colsPerCiphertext
		for voter := 0; voter < layout.votersPerRow; voter++ {
			baseSlotMask[rowBase+voter*blockSize] = 1
		}
	}
	ptBaseSlotMask := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(baseSlotMask, ptBaseSlotMask))

	qExtCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	qBaseCiphertexts := make([]*rlwe.Ciphertext, layout.ciphertextCount)
	for ctIdx := range qExtCiphertexts {
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
		CountOp("EncryptNew")
		qExtCiphertexts[ctIdx] = must1(encryptor.EncryptNew(pt))

		CountOp("MulNew")
		qBaseCiphertexts[ctIdx] = must1(evaluator.MulNew(qExtCiphertexts[ctIdx], ptBaseSlotMask))
		assert(qExtCiphertexts[ctIdx].Level() == params.MaxLevel(), "encrypted q_ext must start at max level")
		assert(qBaseCiphertexts[ctIdx].Level() == qExtCiphertexts[ctIdx].Level(), "base-slot projection must preserve the weight level")
	}
	phWeights.Stop()
	RecordCiphertexts("qExtCiphertexts", qExtCiphertexts)
	RecordCiphertexts("qBaseCiphertexts", qBaseCiphertexts)
	mp_verifyBaseSlotCiphertexts("encrypted q base projection", encoder, params, layout, blockSize, q, qBaseCiphertexts, &cks, P)

	// 4. Tally. From this boundary onward, the homomorphic computation consumes
	// the already-prepared encrypted weight state. Plaintext q appears only in
	// simulation-only verification calls and is never a tally operand.
	// 4.1 - Encrypt and aggregate period inputs and their encrypted range masks.
	phEncrypt := StartPhase("4.1-tally-period-input-and-range-mask-encryption")

	zeroSlots := make([]uint64, params.MaxSlots())
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(zeroSlots, ptZero))

	newEncryptedPeriodGrid := func() [][]*rlwe.Ciphertext {
		grid := make([][]*rlwe.Ciphertext, T)
		for period := range T {
			grid[period] = make([]*rlwe.Ciphertext, layout.ciphertextCount)
			for ctIdx := range layout.ciphertextCount {
				CountOp("EncryptNew")
				grid[period][ctIdx] = must1(encryptor.EncryptNew(ptZero))
			}
		}
		return grid
	}

	// Each period has four independently encrypted aggregate inputs: candidate
	// values, candidate range masks, delegation values, and delegation range
	// masks. An individual range mask has ones only across the submitting
	// voter's logical width (b or k); common-block padding and all other voter
	// blocks remain zero.
	candidatePeriodInputs := newEncryptedPeriodGrid()
	candidateRangeMaskCiphertexts := newEncryptedPeriodGrid()
	delegationPeriodInputs := newEncryptedPeriodGrid()
	delegationRangeMaskCiphertexts := newEncryptedPeriodGrid()

	slotBuf := make([]uint64, params.MaxSlots())
	rangeMaskBuf := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())
	inputCount := countPeriodicSubmissions(candidatePeriods) + countPeriodicSubmissions(delegationPeriods)
	encProg := NewProgress("4.1-tally-period-input-and-range-mask-encryption", int64(2*inputCount))

	// encryptAndAccumulate encrypts one simulated input or its corresponding
	// range mask under the collective public key and adds it to the appropriate
	// period aggregate.
	encryptAndAccumulate := func(dst []*rlwe.Ciphertext, ctIdx int, slots []uint64) {
		CountOp("Encode")
		must(encoder.Encode(slots, ptInput))
		CountOp("EncryptNew")
		ct := must1(encryptor.EncryptNew(ptInput))
		CountOp("Add")
		must(evaluator.Add(dst[ctIdx], ct, dst[ctIdx]))
		encProg.Inc()
	}

	for period := range T {
		for voter := range n {
			ctIdx := voter / layout.votersPerCiphertext
			localIdx := voter % layout.votersPerCiphertext
			rowInCt := localIdx / layout.votersPerRow
			voterInRow := localIdx % layout.votersPerRow
			blockStart := rowInCt*layout.colsPerCiphertext + voterInRow*blockSize

			if choice := candidatePeriods[period][voter]; choice >= 0 {
				slotBuf[blockStart+choice] = 1
				encryptAndAccumulate(candidatePeriodInputs[period], ctIdx, slotBuf)
				slotBuf[blockStart+choice] = 0

				for offset := 0; offset < b; offset++ {
					rangeMaskBuf[blockStart+offset] = 1
				}
				encryptAndAccumulate(candidateRangeMaskCiphertexts[period], ctIdx, rangeMaskBuf)
				for offset := 0; offset < b; offset++ {
					rangeMaskBuf[blockStart+offset] = 0
				}
			}

			if choice := delegationPeriods[period][voter]; choice >= 0 {
				slotBuf[blockStart+choice] = 1
				encryptAndAccumulate(delegationPeriodInputs[period], ctIdx, slotBuf)
				slotBuf[blockStart+choice] = 0

				for offset := 0; offset < k; offset++ {
					rangeMaskBuf[blockStart+offset] = 1
				}
				encryptAndAccumulate(delegationRangeMaskCiphertexts[period], ctIdx, rangeMaskBuf)
				for offset := 0; offset < k; offset++ {
					rangeMaskBuf[blockStart+offset] = 0
				}
			}
		}
	}
	encProg.Finish()
	phEncrypt.Stop()

	flattenPeriodGrid := func(grid [][]*rlwe.Ciphertext) []*rlwe.Ciphertext {
		flat := make([]*rlwe.Ciphertext, 0, T*layout.ciphertextCount)
		for period := range grid {
			flat = append(flat, grid[period]...)
		}
		return flat
	}
	RecordCiphertexts("candidatePeriodInputs", flattenPeriodGrid(candidatePeriodInputs))
	RecordCiphertexts("candidateRangeMaskCiphertexts", flattenPeriodGrid(candidateRangeMaskCiphertexts))
	RecordCiphertexts("delegationPeriodInputs", flattenPeriodGrid(delegationPeriodInputs))
	RecordCiphertexts("delegationRangeMaskCiphertexts", flattenPeriodGrid(delegationRangeMaskCiphertexts))

	// 4.2 - Apply the encrypted periodic echo recurrence independently to the
	// candidate and delegation states. The public logical-range vectors below
	// represent the constant 1 in (1-z^p); they are not per-input range masks.
	phEcho := StartPhase(fmt.Sprintf("4.2-tally-periodic-echo-%s", echoMode))
	candidateLogicalRanges := make([][]uint64, layout.ciphertextCount)
	delegationLogicalRanges := make([][]uint64, layout.ciphertextCount)
	for ctIdx := range layout.ciphertextCount {
		candidateLogicalRanges[ctIdx] = make([]uint64, params.MaxSlots())
		delegationLogicalRanges[ctIdx] = make([]uint64, params.MaxSlots())
		votersInCt := min(layout.votersPerCiphertext, n-ctIdx*layout.votersPerCiphertext)
		for localVoterIdx := range votersInCt {
			blockStart := (localVoterIdx / layout.votersPerRow) * layout.colsPerCiphertext
			blockStart += (localVoterIdx % layout.votersPerRow) * blockSize
			for offset := 0; offset < b; offset++ {
				candidateLogicalRanges[ctIdx][blockStart+offset] = 1
			}
			for offset := 0; offset < k; offset++ {
				delegationLogicalRanges[ctIdx][blockStart+offset] = 1
			}
		}
	}

	buildOneMinusMasks := func(encryptedMasks [][]*rlwe.Ciphertext, logicalRanges [][]uint64) [][]*rlwe.Ciphertext {
		oneMinusMasks := make([][]*rlwe.Ciphertext, T)
		for period := range T {
			oneMinusMasks[period] = make([]*rlwe.Ciphertext, layout.ciphertextCount)
			for ctIdx := range layout.ciphertextCount {
				CountOp("MulNew")
				ctNegMask := must1(evaluator.MulNew(encryptedMasks[period][ctIdx], -1))
				CountOp("AddNew")
				oneMinusMasks[period][ctIdx] = must1(evaluator.AddNew(ctNegMask, logicalRanges[ctIdx]))
			}
		}
		return oneMinusMasks
	}

	mulRelinEcho := func(left, right *rlwe.Ciphertext) *rlwe.Ciphertext {
		CountOp("MulRelinNew")
		product := must1(evaluator.MulRelinNew(left, right))
		assert(product.Level() == min(left.Level(), right.Level()), "scale-invariant echo multiplication must preserve the minimum input level")
		return product
	}

	applyPeriodicEchoTree := func(inputs, oneMinusMasks [][]*rlwe.Ciphertext) []*rlwe.Ciphertext {
		// Each period is represented as an affine transition on (u, total),
		// and the transitions are composed in a balanced tree. This evaluates
		// the exact recurrence with logarithmic multiplicative depth.
		add := func(left, right *rlwe.Ciphertext) *rlwe.Ciphertext {
			CountOp("AddNew")
			return must1(evaluator.AddNew(left, right))
		}

		// A segment maps an incoming state (u, total) to:
		//
		//   u'     = a*u + b
		//   total' = total + c*u + d
		//
		// One period has (a,b,c,d)=(1-z,input,1-z,input). If left is
		// followed by right, their composition is associative and can therefore
		// be evaluated as a balanced tree.
		type echoSegment struct {
			a, b, c, d *rlwe.Ciphertext
		}
		compose := func(left, right echoSegment) echoSegment {
			a := mulRelinEcho(right.a, left.a)
			b := add(mulRelinEcho(right.a, left.b), right.b)
			c := add(left.c, mulRelinEcho(right.c, left.a))
			d := add(add(left.d, right.d), mulRelinEcho(right.c, left.b))
			return echoSegment{a: a, b: b, c: c, d: d}
		}

		totals := make([]*rlwe.Ciphertext, layout.ciphertextCount)
		for ctIdx := range layout.ciphertextCount {
			var composeRange func(start, end int) echoSegment
			composeRange = func(start, end int) echoSegment {
				if start == end {
					return echoSegment{
						a: oneMinusMasks[start][ctIdx],
						b: inputs[start][ctIdx],
						c: oneMinusMasks[start][ctIdx],
						d: inputs[start][ctIdx],
					}
				}
				middle := (start + end) / 2
				return compose(composeRange(start, middle), composeRange(middle+1, end))
			}

			// The initial state is u^-1=0 and total^-1=0, so the completed
			// segment's d component is exactly total^(T-1).
			totals[ctIdx] = composeRange(0, T-1).d
		}

		return totals
	}

	applyPeriodicEchoSequential := func(inputs, oneMinusMasks [][]*rlwe.Ciphertext) []*rlwe.Ciphertext {
		// Literal streaming recurrence:
		//   u^p = u^(p-1)*(1-z^p) + input^p
		//   total^p = total^(p-1) + u^p
		// Only u is refreshed between chunks because it feeds the next
		// multiplication. The completed total is refreshed by the common final
		// refresh below.
		current := make([]*rlwe.Ciphertext, layout.ciphertextCount)
		totals := make([]*rlwe.Ciphertext, layout.ciphertextCount)
		for ctIdx := range layout.ciphertextCount {
			current[ctIdx] = inputs[0][ctIdx].CopyNew()
			totals[ctIdx] = current[ctIdx].CopyNew()
		}

		transitionsSinceRefresh := 0
		for period := 1; period < T; period++ {
			for ctIdx := range layout.ciphertextCount {
				carried := mulRelinEcho(current[ctIdx], oneMinusMasks[period][ctIdx])
				CountOp("AddNew")
				current[ctIdx] = must1(evaluator.AddNew(carried, inputs[period][ctIdx]))
				CountOp("Add")
				must(evaluator.Add(totals[ctIdx], current[ctIdx], totals[ctIdx]))
			}

			transitionsSinceRefresh++
			if period < T-1 && transitionsSinceRefresh == echoRefreshInterval {
				CountOp("SequentialStateRefreshBoundary")
				for ctIdx := range current {
					current[ctIdx] = collectiveRefresh(current[ctIdx], P, params, crs)
				}
				transitionsSinceRefresh = 0
			}
		}
		return totals
	}

	candidateOneMinusMasks := buildOneMinusMasks(candidateRangeMaskCiphertexts, candidateLogicalRanges)
	delegationOneMinusMasks := buildOneMinusMasks(delegationRangeMaskCiphertexts, delegationLogicalRanges)
	var vCiphertexts, dCiphertexts []*rlwe.Ciphertext
	if echoMode == "tree" {
		vCiphertexts = applyPeriodicEchoTree(candidatePeriodInputs, candidateOneMinusMasks)
		dCiphertexts = applyPeriodicEchoTree(delegationPeriodInputs, delegationOneMinusMasks)
	} else {
		vCiphertexts = applyPeriodicEchoSequential(candidatePeriodInputs, candidateOneMinusMasks)
		dCiphertexts = applyPeriodicEchoSequential(delegationPeriodInputs, delegationOneMinusMasks)
	}

	// Both strategies return the same encrypted total. Refresh it once before
	// the shared majority-selection pipeline; tree mode needs this after its
	// wider circuit, and sequential mode needs it after accumulating all u^p.
	CountOp("FinalEchoRefreshBoundary")
	for ctIdx := range layout.ciphertextCount {
		vCiphertexts[ctIdx] = collectiveRefresh(vCiphertexts[ctIdx], P, params, crs)
		dCiphertexts[ctIdx] = collectiveRefresh(dCiphertexts[ctIdx], P, params, crs)
	}
	phEcho.Stop()
	RecordCiphertexts("vCiphertexts", vCiphertexts)
	RecordCiphertexts("dCiphertexts", dCiphertexts)
	mp_verifyPackedCiphertexts("candidate periodic echo total", encoder, params, layout, blockSize, b, v, vCiphertexts, &cks, P)
	mp_verifyPackedCiphertexts("delegation periodic echo total", encoder, params, layout, blockSize, k, d, dCiphertexts, &cks, P)

	// 4.3 - Lagrange interpolation I(x > T/2)
	// decryptor := bgv.NewDecryptor(params, tsk) // COMMENTED OUT FOR MULTIPARTY CASE
	phIndicator := StartPhase("4.3-tally-lagrange-indicator")
	indicatorCoeffs := lagrangeIndicatorCoefficients(T, params.PlaintextModulus())
	indicatorDegree := len(indicatorCoeffs) - 1
	indicatorProg := NewProgress("4.3-tally-lagrange-indicator", int64(len(vCiphertexts)+len(dCiphertexts)))
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
	//verifyIndicatorCiphertexts("t after indicator", decryptor, encoder, params, layout, blockSize, b, v, vCiphertexts, T)
	//verifyIndicatorCiphertexts("d after indicator", decryptor, encoder, params, layout, blockSize, k, d, dCiphertexts, T)
	mp_verifyIndicatorCiphertexts("t after indicator", encoder, params, layout, blockSize, b, v, vCiphertexts, T, &cks, P)
	mp_verifyIndicatorCiphertexts("d after indicator", encoder, params, layout, blockSize, k, d, dCiphertexts, T, &cks, P)

	// 4.4 - Aggregate row of d using the prepared encrypted q_ext input
	phSupport := StartPhase("4.4-tally-delegate-support")
	assert(len(dCiphertexts) > 0, "dCiphertexts must be > 0")

	dWeighted := make([]*rlwe.Ciphertext, len(dCiphertexts))
	for ctIdx, ct := range dCiphertexts {
		CountOp("MulRelinNew")
		dWeighted[ctIdx] = must1(evaluator.MulRelinNew(ct, qExtCiphertexts[ctIdx]))
		assert(dWeighted[ctIdx].Level() == min(ct.Level(), qExtCiphertexts[ctIdx].Level()), "encrypted q_ext multiplication must preserve the minimum input level")
	}
	fmt.Printf(
		"Encrypted q_ext levels: weight=%d, delegation-indicator=%d, product-after-relinearization=%d\n",
		qExtCiphertexts[0].Level(),
		dCiphertexts[0].Level(),
		dWeighted[0].Level(),
	)
	mp_verifyPackedCiphertexts(
		"encrypted d' * q_ext",
		encoder,
		params,
		layout,
		blockSize,
		k,
		weightedDelegationIndicatorPlain(d, q, n, k, T),
		dWeighted,
		&cks,
		P,
	)

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
	//verifyLeadingSlotsCiphertext("delegate support", decryptor, encoder, params, delegateSupportPlain(d, q, n, k, T), ctDelegateSupport)
	mp_verifyLeadingSlotsCiphertext("delegate support", encoder, params, delegateSupportPlain(d, q, n, k, T), ctDelegateSupport, &cks, P)

	// 4.5 - Computing the weighted self-power vector dTilde * q
	phDTilde := StartPhase("4.5-tally-dTilde")
	dTildeCiphertexts := make([]*rlwe.Ciphertext, len(dCiphertexts))
	for ctIdx, wCt := range dCiphertexts {
		// Sum each voter's k delegation slots into their block's base slot with a
		// logarithmic-depth inner sum (ceil(log2 k) rotations) instead of a linear
		// scan of k-1 rotations. RotateAndAdd(wCt, 1, k) sets slot i to the sum of
		// slots i..i+k-1, so every voter's base slot holds its k-slot delegation
		// total; the mask below keeps only those base slots. Relies on the
		// InnerSum(1, k) Galois keys generated in the setup phase.
		//
		// Majority selection leaves at most one nonzero slot per block. First
		// compute the encrypted boolean dTilde = 1 - sum at the base slots, using
		// only the public structural base-slot mask. Then multiply dTilde by the
		// encrypted base-slot q vector. This avoids adding two ciphertexts with
		// different invariant-tensoring scales while still computing
		// q_i*(1-sum): a self-delegating voter keeps their own power, a delegating
		// voter drops to 0.
		ctRowSums := bgv.NewCiphertext(params, 1, wCt.Level())
		CountOp("RotateAndAdd")
		must(evaluator.RotateAndAdd(wCt, 1, k, ctRowSums))

		CountOp("MulNew")
		ctNegRowSums := must1(evaluator.MulNew(ctRowSums, -1))
		CountOp("AddNew")
		ctSelfIndicator := must1(evaluator.AddNew(ctNegRowSums, baseSlotMask))
		CountOp("MulRelinNew")
		dTildeCiphertexts[ctIdx] = must1(evaluator.MulRelinNew(ctSelfIndicator, qBaseCiphertexts[ctIdx]))
		assert(dTildeCiphertexts[ctIdx].Level() == min(ctSelfIndicator.Level(), qBaseCiphertexts[ctIdx].Level()), "encrypted base-weight multiplication must preserve the minimum input level")
		if ctIdx == 0 {
			fmt.Printf(
				"Encrypted base-weight levels: weight=%d, delegation-row-sum=%d, self-indicator=%d, product-after-relinearization=%d\n",
				qBaseCiphertexts[ctIdx].Level(),
				ctRowSums.Level(),
				ctSelfIndicator.Level(),
				dTildeCiphertexts[ctIdx].Level(),
			)
		}
	}
	phDTilde.Stop()
	RecordCiphertexts("dTildeCiphertexts", dTildeCiphertexts)
	//verifyBaseSlotCiphertexts("dTilde", decryptor, encoder, params, layout, blockSize, weightedSelfPowerPlain(d, q, n, k, T), dTildeCiphertexts)
	mp_verifyBaseSlotCiphertexts("dTilde", encoder, params, layout, blockSize, weightedSelfPowerPlain(d, q, n, k, T), dTildeCiphertexts, &cks, P)

	// 4.6 - Compute the voter weights votWeights = Dw + dTilde
	// Precompute one-hot target mask plaintexts indexed by local voter position within a ciphertext.
	phDw := StartPhase("4.6-tally-Dw+dTilde")
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
	//verifyBaseSlotCiphertexts("encrypted D w_d", decryptor, encoder, params, layout, blockSize, expectedDw, dwCiphertexts)
	//verifyBaseSlotCiphertexts("Dw_d + dTilde", decryptor, encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, d, q, n, k, T), voterWeightCiphertexts)
	mp_verifyBaseSlotCiphertexts("encrypted D w_d", encoder, params, layout, blockSize, expectedDw, dwCiphertexts, &cks, P)
	mp_verifyBaseSlotCiphertexts("Dw_d + dTilde", encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, d, q, n, k, T), voterWeightCiphertexts, &cks, P)

	// 4.7 - Product of t and w, followed by packed aggregation
	phTally := StartPhase("4.7-tally-vote-weight-product")
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

	// 5. Threshold-decrypt and verify against the plaintext reference.
	phDecrypt := StartPhase("5-threshold-decrypt-verify")
	CountOp("DecryptNew")
	// ptResult := decryptor.DecryptNew(ctResult)
	ptResult := thresholdDecrypt(ctResult, P, &cks, params)
	decoded := make([]uint64, params.MaxSlots())
	CountOp("Decode")
	must(encoder.Decode(ptResult, decoded))
	// decoded := append([]uint64(nil), slots[:b]...)
	phDecrypt.Stop()
	fmt.Println("decrypted final tally =", decoded[:b])
	//verifyLeadingSlotsCiphertext("final tally", decryptor, encoder, params, delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T), ctResult)
	mp_verifyLeadingSlotsCiphertext("final tally", encoder, params, delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T), ctResult, &cks, P)
}
