package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	bgvpoly "github.com/tuneinsight/lattigo/v6/circuits/bgv/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"

	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	benchmarkMode := len(os.Args) > 1 && os.Args[1] == "benchmark"
	if benchmarkMode {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}

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
	refreshModeFlag := flag.String("refresh-mode", "collective", "ciphertext refresh strategy: collective or none")
	echoRefreshIntervalFlag := flag.Int("echo-refresh-interval", 1, "sequential echo transitions between collective refreshes")
	diagnosticChecksFlag := flag.String("diagnostic-checks", "all", "threshold-decryption checks: all or final")
	metricsSampleIntervalFlag := flag.Duration("metrics-sample-interval", time.Second, "interval for phase-level CPU and memory samples")
	parameterProfileFlag := flag.String("parameter-profile", "legacy", "named BGV parameter profile")
	parameterFileFlag := flag.String("parameter-file", "", "versioned exact-prime parameter JSON; overrides named profile")
	describeParametersFlag := flag.Bool("describe-parameters", false, "print concrete parameter JSON and exit before key generation")
	workloadSeedFlag := flag.String("workload-seed", "", "reproducible synthetic workload seed; encryption and keys remain independently random")
	outputRootFlag := flag.String("output-root", "runs", "directory for unique run subdirectories")
	noiseCheckFlag := flag.Bool("noise-check", false, "diagnostic-only secret-assisted coefficient noise checks; enables all plaintext checks")
	noiseMarginFlag := flag.Float64("noise-margin-min", 20, "minimum coefficient noise margin in diagnostic mode")
	benchmarkSampleVoters := 0
	if benchmarkMode {
		flag.IntVar(&benchmarkSampleVoters, "sample-voters", 1000, "voter-period aggregation samples to measure")
	}
	flag.Parse()
	assert(len(flag.Args()) == 0, "unexpected positional arguments")

	n := *nFlag
	b := *bFlag
	k := *kFlag
	T := *TFlag
	qMax := *qMaxFlag
	progressEnabled = *progressFlag
	N := *NFlag
	echoMode := *echoModeFlag
	refreshMode := *refreshModeFlag
	echoRefreshInterval := *echoRefreshIntervalFlag
	diagnosticChecks := *diagnosticChecksFlag
	if *noiseCheckFlag {
		diagnosticChecks = "all"
	}
	if benchmarkMode {
		diagnosticChecks = "final"
	}
	metricsSampleInterval := *metricsSampleIntervalFlag
	assert(!(*noiseCheckFlag && benchmarkMode), "reused benchmark fixtures cannot validate noise")
	assert(*noiseMarginFlag >= 0, "noise margin threshold must be nonnegative")
	assert(n > 0 && b > 0 && k > 0 && k < n && T > 0 && T%2 == 1 && N > 0, "invalid election dimensions")
	setWorkloadSeed(*workloadSeedFlag)
	selectedLiteral, selectedProfile := experimentLiteral(*parameterProfileFlag, *parameterFileFlag, n, qMax)
	if *describeParametersFlag {
		p := must1(bgv.NewParametersFromLiteral(selectedLiteral))
		out := json.NewEncoder(os.Stdout)
		out.SetIndent("", "  ")
		must(out.Encode(concreteExperimentParameters(selectedProfile, p)))
		return
	}
	assert(echoMode == "tree" || echoMode == "sequential", "echo-mode must be tree or sequential")
	assert(refreshMode == "collective" || refreshMode == "none", "refresh-mode must be collective or none")
	assert(diagnosticChecks == "all" || diagnosticChecks == "final", "diagnostic-checks must be all or final")
	assert(!benchmarkMode || benchmarkSampleVoters > 0, "sample-voters must be > 0")
	assert(!benchmarkMode || benchmarkSampleVoters <= n, "sample-voters must be <= n")
	assert(metricsSampleInterval >= time.Millisecond, "metrics-sample-interval must be at least 1ms")
	runIntermediateChecks := diagnosticChecks == "all"
	if echoMode == "sequential" && refreshMode == "collective" {
		assert(echoRefreshInterval > 0, "echo-refresh-interval must be > 0")
	} else {
		// The interval controls only collective intermediate refreshes in
		// sequential mode.
		echoRefreshInterval = 0
	}
	//D := [][]uint64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 1, 0}}
	//d := []uint64{0, 0, 1, 0, 0, 9, 0, 0, 2, 0, 0, 5, 1, 0, 3, 1, 0, 8, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 6}
	//v := []uint64{2, 7, 1, 8, 7, 2, 8, 1, 6, 3, 2, 7, 3, 6, 1, 8, 6, 3, 5, 4}

	InitMetrics(runMeta{
		TallyFlow:            "period-streaming-midpoint-tree-v1",
		OutputRoot:           *outputRootFlag,
		ParameterProfile:     selectedProfile,
		WorkloadSeed:         *workloadSeedFlag,
		EncryptionRandomness: "fresh-unseeded",
		NoiseChecks:          *noiseCheckFlag,
		N:                    n,
		B:                    b,
		K:                    k,
		T:                    T,
		EchoMode:             echoMode,
		RefreshMode:          refreshMode,
		EchoRefreshInterval:  echoRefreshInterval,
		DiagnosticChecks:     diagnosticChecks,
		ExecutionMode:        map[bool]string{false: "fresh", true: "sampled-server-benchmark"}[benchmarkMode],
		BenchmarkSamples:     benchmarkSampleVoters,
		MetricsSampleMS:      metricsSampleInterval.Milliseconds(),
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

	var candidatePeriods, delegationPeriods [][]int
	var validity [][]uint64
	if !benchmarkMode {
		// Retain explicit period schedules so the encrypted tally and plaintext
		// reference can both model periods with no new submission. The initial
		// count vectors are only simulation seeds for generating those schedules.
		candidatePeriods = periodicChoicesFromCounts(randomVotingVector(n, b, T), n, b, T)
		delegationPeriods = periodicChoicesFromCounts(randomDelegationVector(n, k, T), n, k, T)
		ensureEchoCarryEvent(candidatePeriods)
		ensureEchoCarryEvent(delegationPeriods)
		validity = registrationValidityBits(T, n)
		addValidityGatingScenario(candidatePeriods, validity, b)
		addValidityGatingScenario(delegationPeriods, validity, k)
		verifyValidityGatingScenario(candidatePeriods, validity, b)
		verifyValidityGatingScenario(delegationPeriods, validity, k)
	}

	// Full plaintext echo vectors are needed only by the intermediate diagnostic
	// checks. Final-only mode deliberately avoids keeping these n*b and n*k
	// reference matrices live alongside the encrypted tally.
	var v, d []uint64
	if runIntermediateChecks {
		v = periodicEchoTotalsPlain(candidatePeriods, validity, n, b)
		d = periodicEchoTotalsPlain(delegationPeriods, validity, n, k)
	}
	q := randomVotingPower(n, qMax) // per-voter voting power q_i, one entry per voter
	// fmt.Println("D=", D)
	// fmt.Println("d=", d)
	// fmt.Println("v=", v)
	// fmt.Println("q=", q)
	RecordSized("D_matrix", n, int64(k)*8, "n rows of k uint64 (one-hot)")
	if !benchmarkMode {
		RecordSized("delegation_periods", T, int64(n)*8, "period-major choice indices; -1 means no submission")
		RecordSized("candidate_periods", T, int64(n)*8, "period-major choice indices; -1 means no submission")
		RecordSized("registration_validity", T, int64(n)*8, "one simulated private validity bit per voter-period, shared by candidate and delegation inputs")
	}
	if runIntermediateChecks {
		RecordSized("d_vector", 1, int64(n)*int64(k)*8, "flat n*k uint64 after plaintext echo simulation")
		RecordSized("t_vector", 1, int64(n)*int64(b)*8, "flat n*b uint64 after plaintext echo simulation")
	}
	RecordSized("q_vector", 1, int64(n)*8, "flat n uint64 voting power")
	phInit.Stop()

	// 2. Parameters and Keys setup
	phSetup := StartPhase("2-bgv-setup")
	// Named profiles use the declared n*qmax bound so workload seeds cannot
	// change the plaintext modulus. An exact parameter file may use a larger
	// compatible modulus, but must still cover that bound.
	qSum := sumUint64(q)

	paramsLiteral := selectedLiteral

	// Build BGV crypto context.
	rlweLiteral := paramsLiteral.GetRLWEParametersLiteral()
	rlweLiteral.RingType = ring.Standard
	rlweParams := must1(rlwe.NewParametersFromLiteral(rlweLiteral))
	params := must1(bgv.NewParameters(rlweParams, paramsLiteral.PlaintextModulus))
	SetBGVParams(params.ParametersLiteral())
	rec.meta.ParameterID = experimentParameterID(concreteExperimentParameters(selectedProfile, params))
	must(writeMeta())

	/****** COMMENTED OUT FOR MULTIPARY CASE ******/
	// kgen := bgv.NewKeyGenerator(params)
	// sk, pk := kgen.GenKeyPairNew()
	/******************************************/

	fmt.Println("Plaintext modulus =", params.PlaintextModulus())
	fmt.Println("Ring type =", params.RingType())
	fmt.Println("Slots =", params.MaxSlots())
	fmt.Println("Dimensions =", params.MaxDimensions())
	fmt.Println("Total voting power sum(q) =", qSum)
	fmt.Println("Echo mode =", echoMode, "refresh mode =", refreshMode, "sequential refresh interval =", echoRefreshInterval, "diagnostic checks =", diagnosticChecks)
	if benchmarkMode {
		fmt.Println("Execution mode = sampled server benchmark; aggregation samples =", benchmarkSampleVoters)
	} else {
		fmt.Println("Execution mode = fresh")
	}
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
	if *noiseCheckFlag {
		startNoiseDiagnostics(params, encoder, evaluator, P, *noiseMarginFlag)
		defer finishNoiseDiagnostics()
	}
	phSetup.Stop()
	RecordRelinKey("rlk", rlk)
	RecordGaloisKeys("galois_keys", gks)
	RecordSized("galois_elements", len(galEls), 8, "uint64 indices fed to GenGaloisKeysNew")

	// 3. Pre-election input preparation.
	//
	// The plaintext weights are available here only because this executable
	// simulates pre-election input preparation and plaintext correctness checks.
	// The tally begins below with the weight state already encrypted under the
	// collective public key.
	phInputs := StartPhase("3-pre-election-weight-input-preparation")

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

	phInputs.Stop()
	RecordCiphertexts("qExtCiphertexts", qExtCiphertexts)
	RecordCiphertexts("qBaseCiphertexts", qBaseCiphertexts)
	if runIntermediateChecks {
		mp_verifyBaseSlotCiphertexts("encrypted q base projection", encoder, params, layout, blockSize, q, qBaseCiphertexts, &cks, P)
	}

	// The server benchmark prepares scale-compatible encrypted-zero operands
	// outside the measured aggregation sample.
	var benchmarkInputs *benchmarkInputCiphertexts
	if benchmarkMode {
		phFixtures := StartPhase("3.1-benchmark-input-fixture-preparation")
		benchmarkInputs = prepareBenchmarkInputCiphertexts(params, encoder, encryptor)
		phFixtures.Stop()
		RecordCiphertexts("benchmarkInputFixtures", []*rlwe.Ciphertext{benchmarkInputs.validity, benchmarkInputs.input})
	}

	// 4. Consume one period at a time, closing it through echo before the next.
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

	newEcho := func() *periodicEchoState {
		return newPeriodicEchoState(T, layout.ciphertextCount, echoMode, evaluator,
			func(period int) bool {
				return refreshMode == "collective" && period > 0 && period < T-1 && period%echoRefreshInterval == 0
			},
			func(ct *rlwe.Ciphertext) *rlwe.Ciphertext { return collectiveRefresh(ct, P, params, crs) })
	}
	candidateEcho, delegationEcho := newEcho(), newEcho()
	var inputAccounting encryptedPeriodAggregates
	for period := range T {
		phEncrypt := StartPhase("4.1-streamed-input-reception-and-validity-gating")
		periodAggregates := streamAndAggregatePeriodInputs(
			params, encoder, encryptor, evaluator, layout, blockSize, b, k,
			n, T, period, candidatePeriods, delegationPeriods, validity, benchmarkSampleVoters, benchmarkInputs,
		)
		phEncrypt.Stop()
		inputAccounting.aggregateInitWall += periodAggregates.aggregateInitWall
		inputAccounting.aggregateInitCPU += periodAggregates.aggregateInitCPU
		inputAccounting.clientPreparationWall += periodAggregates.clientPreparationWall
		inputAccounting.clientPreparationCPU += periodAggregates.clientPreparationCPU
		inputAccounting.serverIngestionWall += periodAggregates.serverIngestionWall
		inputAccounting.serverIngestionCPU += periodAggregates.serverIngestionCPU
		inputAccounting.validityCiphertextCount += periodAggregates.validityCiphertextCount
		if periodAggregates.validityCiphertextBytes != 0 {
			inputAccounting.validityCiphertextBytes = periodAggregates.validityCiphertextBytes
		}

		RecordCiphertexts(fmt.Sprintf("candidatePeriodInputs/p%d", period), periodAggregates.candidateInputs)
		RecordCiphertexts(fmt.Sprintf("candidateRangeMaskCiphertexts/p%d", period), periodAggregates.candidateRangeMasks)
		RecordCiphertexts(fmt.Sprintf("delegationPeriodInputs/p%d", period), periodAggregates.delegationInputs)
		RecordCiphertexts(fmt.Sprintf("delegationRangeMaskCiphertexts/p%d", period), periodAggregates.delegationRangeMasks)
		if runIntermediateChecks {
			candidatePayloadPlain, candidateMaskPlain := gatedPeriodPlain(candidatePeriods[period], validity[period], n, b)
			delegationPayloadPlain, delegationMaskPlain := gatedPeriodPlain(delegationPeriods[period], validity[period], n, k)
			mp_verifyPackedCiphertexts(fmt.Sprintf("candidate gated payload period %d", period), encoder, params, layout, blockSize, b, candidatePayloadPlain, periodAggregates.candidateInputs, &cks, P)
			mp_verifyPackedCiphertexts(fmt.Sprintf("candidate gated range mask period %d", period), encoder, params, layout, blockSize, b, candidateMaskPlain, periodAggregates.candidateRangeMasks, &cks, P)
			mp_verifyPackedCiphertexts(fmt.Sprintf("delegation gated payload period %d", period), encoder, params, layout, blockSize, k, delegationPayloadPlain, periodAggregates.delegationInputs, &cks, P)
			mp_verifyPackedCiphertexts(fmt.Sprintf("delegation gated range mask period %d", period), encoder, params, layout, blockSize, k, delegationMaskPlain, periodAggregates.delegationRangeMasks, &cks, P)
		}
		phEcho := StartPhase(fmt.Sprintf("4.2-tally-periodic-echo-%s", echoMode))
		candidateEcho.ClosePeriod(periodAggregates.candidateInputs, periodAggregates.candidateRangeMasks, candidateLogicalRanges)
		delegationEcho.ClosePeriod(periodAggregates.delegationInputs, periodAggregates.delegationRangeMasks, delegationLogicalRanges)
		// No period grids are retained by main. Echo owns only its running state
		// or completed tree segments; the next iteration creates fresh zeros.
		periodAggregates = encryptedPeriodAggregates{}
		phEcho.Stop()
	}
	vCiphertexts, dCiphertexts := candidateEcho.Totals(), delegationEcho.Totals()
	candidateEcho, delegationEcho = nil, nil
	RecordComponentTiming(
		"4.1-aggregate-initialization",
		inputAccounting.aggregateInitWall,
		inputAccounting.aggregateInitCPU,
		"server-side creation of encrypted zero period aggregates; excludes streamed voter inputs",
	)
	RecordComponentTiming(
		"4.1-simulated-client-input-preparation",
		inputAccounting.clientPreparationWall,
		inputAccounting.clientPreparationCPU,
		fmt.Sprintf("execution-mode=%s; encoding and encryption of incoming validity, payload, and range-mask ciphertexts; excluded from server ingestion time", map[bool]string{false: "fresh", true: "sampled-server-benchmark"}[benchmarkMode]),
	)
	RecordComponentTiming(
		"4.1-server-validity-gating-and-aggregation",
		inputAccounting.serverIngestionWall,
		inputAccounting.serverIngestionCPU,
		"ciphertext validity gates and additions into period aggregates; contains no input encoding or encryption",
	)
	fmt.Printf(
		"Input reception components: aggregate initialization=%s, simulated client preparation=%s, server gating/aggregation=%s\n",
		inputAccounting.aggregateInitWall,
		inputAccounting.clientPreparationWall,
		inputAccounting.serverIngestionWall,
	)
	if benchmarkMode {
		estimatedAggregation := time.Duration(float64(inputAccounting.serverIngestionWall) * float64(n*T) / float64(benchmarkSampleVoters))
		RecordComponentTiming(
			"4.1-estimated-full-server-validity-gating-and-aggregation",
			estimatedAggregation,
			time.Duration(float64(inputAccounting.serverIngestionCPU)*float64(n*T)/float64(benchmarkSampleVoters)),
			fmt.Sprintf("extrapolated from %d combined voter-period samples to n*T=%d; estimate, not directly measured", benchmarkSampleVoters, n*T),
		)
		fmt.Printf("Estimated full server gating/aggregation for n*T=%d: %s\n", n*T, estimatedAggregation)
	}
	if benchmarkMode {
		RecordSized(
			"sampled_validity_ciphertexts",
			inputAccounting.validityCiphertextCount,
			inputAccounting.validityCiphertextBytes,
			"benchmark sample count only; not a communication estimate",
		)
	} else {
		RecordSized(
			"validity_ciphertexts_received",
			inputAccounting.validityCiphertextCount,
			inputAccounting.validityCiphertextBytes,
			"serialized input traffic estimate; ciphertexts are consumed one at a time and are not retained",
		)
	}
	// In collective mode, refresh the completed echo totals before the shared
	// majority-selection pipeline. No-refresh mode deliberately skips this
	// boundary so parameter sufficiency can be tested end to end.
	if refreshMode == "collective" {
		phEcho := StartPhase(fmt.Sprintf("4.2-tally-periodic-echo-%s", echoMode))
		CountOp("FinalEchoRefreshBoundary")
		for ctIdx := range layout.ciphertextCount {
			vCiphertexts[ctIdx] = collectiveRefresh(vCiphertexts[ctIdx], P, params, crs)
			dCiphertexts[ctIdx] = collectiveRefresh(dCiphertexts[ctIdx], P, params, crs)
		}
		phEcho.Stop()
	}
	RecordCiphertexts("vCiphertexts", vCiphertexts)
	RecordCiphertexts("dCiphertexts", dCiphertexts)
	if runIntermediateChecks {
		mp_verifyPackedCiphertexts("candidate periodic echo total", encoder, params, layout, blockSize, b, v, vCiphertexts, &cks, P)
		mp_verifyPackedCiphertexts("delegation periodic echo total", encoder, params, layout, blockSize, k, d, dCiphertexts, &cks, P)
	}

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
	recordNoiseCheckpoint("candidate_indicator", vCiphertexts)
	recordNoiseCheckpoint("delegation_indicator", dCiphertexts)
	phIndicator.Stop()
	//verifyIndicatorCiphertexts("t after indicator", decryptor, encoder, params, layout, blockSize, b, v, vCiphertexts, T)
	//verifyIndicatorCiphertexts("d after indicator", decryptor, encoder, params, layout, blockSize, k, d, dCiphertexts, T)
	if runIntermediateChecks {
		mp_verifyIndicatorCiphertexts("t after indicator", encoder, params, layout, blockSize, b, v, vCiphertexts, T, &cks, P)
		mp_verifyIndicatorCiphertexts("d after indicator", encoder, params, layout, blockSize, k, d, dCiphertexts, T, &cks, P)
	}

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
	if runIntermediateChecks {
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
	if runIntermediateChecks {
		mp_verifyLeadingSlotsCiphertext("delegate support", encoder, params, delegateSupportPlain(d, q, n, k, T), ctDelegateSupport, &cks, P)
	}

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
	if runIntermediateChecks {
		mp_verifyBaseSlotCiphertexts("dTilde", encoder, params, layout, blockSize, weightedSelfPowerPlain(d, q, n, k, T), dTildeCiphertexts, &cks, P)
	}

	// 4.6 - Compute the voter weights votWeights = Dw + dTilde
	// Precompute one-hot target mask plaintexts indexed by local voter position within a ciphertext.
	phDw := StartPhase("4.6-tally-Dw+dTilde")
	targetMaskPts := make([]*rlwe.Plaintext, layout.votersPerCiphertext)
	for localVoterIdx := range min(n, layout.votersPerCiphertext) {
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
	if runIntermediateChecks {
		// Verification of Dw + dTilde.
		expectedDw := make([]uint64, n)
		delegateSupport := delegateSupportPlain(d, q, n, k, T)
		for i := 0; i < n; i++ {
			for l := 0; l < k; l++ {
				expectedDw[i] += D[i][l] * delegateSupport[l]
			}
		}
		mp_verifyBaseSlotCiphertexts("encrypted D w_d", encoder, params, layout, blockSize, expectedDw, dwCiphertexts, &cks, P)
		mp_verifyBaseSlotCiphertexts("Dw_d + dTilde", encoder, params, layout, blockSize, delegatedVoterWeightsPlain(D, d, q, n, k, T), voterWeightCiphertexts, &cks, P)
	}

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
	var expectedFinal []uint64
	if runIntermediateChecks {
		expectedFinal = delegatedMaskedTallyPlain(D, d, v, q, n, b, k, T)
	} else {
		if benchmarkMode {
			// Benchmark payload and range-mask fixtures encrypt zero.
			expectedFinal = make([]uint64, b)
		} else {
			expectedFinal = delegatedMaskedTallyFromPeriodsPlain(
				D, candidatePeriods, delegationPeriods, validity, q, n, b, k, T,
			)
		}
	}
	verifyLeadingSlots("final tally", expectedFinal, decoded[:b])
}
