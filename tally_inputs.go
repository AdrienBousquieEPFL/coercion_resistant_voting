package main

import (
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// encryptedPeriodAggregates contains the only persistent ciphertext state
// produced while receiving submissions for one period. Each submission contains
// two payload ciphertexts and one shared block-mask ciphertext, all transient.
type encryptedPeriodAggregates struct {
	candidateInputs       []*rlwe.Ciphertext
	delegationInputs      []*rlwe.Ciphertext
	sharedMasks           []*rlwe.Ciphertext
	inputCiphertextCount  int
	inputCiphertextBytes  int64
	aggregateInitWall     time.Duration
	aggregateInitCPU      time.Duration
	clientPreparationWall time.Duration
	clientPreparationCPU  time.Duration
	serverIngestionWall   time.Duration
	serverIngestionCPU    time.Duration
}

// benchmarkInputCiphertexts contains a benchmark-only encrypted-zero fixture.
// All three incoming ciphertexts use the ordinary BGV input scale.
type benchmarkInputCiphertexts struct {
	input *rlwe.Ciphertext
}

func prepareBenchmarkInputCiphertexts(params bgv.Parameters, encoder *bgv.Encoder, encryptor *rlwe.Encryptor) *benchmarkInputCiphertexts {
	zeroSlots := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("EncodeInputFixture")
	must(encoder.Encode(zeroSlots, ptInput))
	CountOp("EncryptInputFixture")
	input := must1(encryptor.EncryptNew(ptInput))

	return &benchmarkInputCiphertexts{input: input}
}

// streamAndAggregatePeriodInputs receives and aggregates one period only.
// The caller consumes the returned accumulators through echo before calling
// again for the next period. Benchmark mode ingests fixtures only in period 0.
// Each simulated submission sends candidate and delegation payloads plus one
// mask over the entire voter block. The server only adds these ciphertexts.
// Commitments and pre-encryption are outside this prototype; fresh encryption
// here simulates client preparation, including submitted all-zero ballots.
func streamAndAggregatePeriodInputs(
	params bgv.Parameters,
	encoder *bgv.Encoder,
	encryptor *rlwe.Encryptor,
	evaluator *bgv.Evaluator,
	layout packingLayout,
	blockSize, candidateWidth, delegationWidth int,
	voterCount, periodCount, period int,
	candidatePeriods, delegationPeriods [][]int,
	benchmarkSampleVoters int,
	benchmarkInputs *benchmarkInputCiphertexts,
) encryptedPeriodAggregates {
	assert(periodCount > 0, "period count must be > 0")
	assert(period >= 0 && period < periodCount, "period index out of range")
	assert(voterCount > 0, "voter count must be > 0")
	benchmarkMode := benchmarkSampleVoters > 0
	assert(!benchmarkMode || benchmarkInputs != nil, "sampled benchmark requires prepared input fixtures")
	assert(!benchmarkMode || benchmarkSampleVoters <= voterCount, "benchmark sample must not exceed voter count")
	if !benchmarkMode {
		assert(len(candidatePeriods) == periodCount, "candidate periods must match period count")
		assert(len(delegationPeriods) == periodCount, "delegation periods must match period count")
	}

	initWallStart := time.Now()
	initCPUStart := cpuTime()
	zeroSlots := make([]uint64, params.MaxSlots())
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(zeroSlots, ptZero))

	newEncryptedPeriodAccumulator := func() []*rlwe.Ciphertext {
		grid := make([]*rlwe.Ciphertext, layout.ciphertextCount)
		for ctIdx := range grid {
			CountOp("EncryptNew")
			grid[ctIdx] = must1(encryptor.EncryptNew(ptZero))
		}
		return grid
	}

	out := encryptedPeriodAggregates{
		candidateInputs:  newEncryptedPeriodAccumulator(),
		delegationInputs: newEncryptedPeriodAccumulator(),
		sharedMasks:      newEncryptedPeriodAccumulator(),
	}
	out.aggregateInitWall = time.Since(initWallStart)
	out.aggregateInitCPU = cpuTime() - initCPUStart

	slotBuf := make([]uint64, params.MaxSlots())
	rangeMaskBuf := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())
	votersToProcess := voterCount
	if benchmarkMode {
		votersToProcess = 0
		if period == 0 {
			votersToProcess = benchmarkSampleVoters
		}
	} else {
		assert(len(candidatePeriods[period]) == voterCount, "candidate period must contain one entry per voter")
		assert(len(delegationPeriods[period]) == voterCount, "delegation period must contain one entry per voter")
	}
	submissions := 0
	for voter := range votersToProcess {
		if benchmarkMode || candidatePeriods[period][voter] != noSubmission || delegationPeriods[period][voter] != noSubmission {
			submissions++
		}
	}
	progress := NewProgress("4.1-streamed-input-reception-and-aggregation", int64(3*submissions))

	encryptAndAccumulate := func(dst []*rlwe.Ciphertext, ctIdx int, slots []uint64) {
		var inputCt *rlwe.Ciphertext
		if benchmarkMode {
			inputCt = benchmarkInputs.input
		} else {
			clientWallStart := time.Now()
			clientCPUStart := cpuTime()
			CountOp("Encode")
			must(encoder.Encode(slots, ptInput))
			CountOp("EncryptNew")
			inputCt = must1(encryptor.EncryptNew(ptInput))
			out.clientPreparationWall += time.Since(clientWallStart)
			out.clientPreparationCPU += cpuTime() - clientCPUStart
		}

		serverWallStart := time.Now()
		serverCPUStart := cpuTime()
		CountOp("Add")
		must(evaluator.Add(dst[ctIdx], inputCt, dst[ctIdx]))
		out.serverIngestionWall += time.Since(serverWallStart)
		out.serverIngestionCPU += cpuTime() - serverCPUStart
		out.inputCiphertextCount++
		out.inputCiphertextBytes = int64(inputCt.BinarySize())
		progress.Inc()
	}

	for voter := range votersToProcess {
		candidateChoice, delegationChoice := 0, 0
		if !benchmarkMode {
			candidateChoice, delegationChoice = candidatePeriods[period][voter], delegationPeriods[period][voter]
		}
		assert(candidateChoice >= zeroSubmission && candidateChoice < candidateWidth, "candidate choice is outside its logical range")
		assert(delegationChoice >= zeroSubmission && delegationChoice < delegationWidth, "delegation choice is outside its logical range")
		mask := submissionMask(candidateChoice, delegationChoice)
		if candidateChoice == noSubmission && delegationChoice == noSubmission {
			continue
		}
		ctIdx := voter / layout.votersPerCiphertext
		localIdx := voter % layout.votersPerCiphertext
		blockStart := (localIdx/layout.votersPerRow)*layout.colsPerCiphertext + (localIdx%layout.votersPerRow)*blockSize
		if candidateChoice >= 0 {
			slotBuf[blockStart+candidateChoice] = 1
		}
		encryptAndAccumulate(out.candidateInputs, ctIdx, slotBuf)
		if candidateChoice >= 0 {
			slotBuf[blockStart+candidateChoice] = 0
		}
		if delegationChoice >= 0 {
			slotBuf[blockStart+delegationChoice] = 1
		}
		encryptAndAccumulate(out.delegationInputs, ctIdx, slotBuf)
		if delegationChoice >= 0 {
			slotBuf[blockStart+delegationChoice] = 0
		}
		for offset := range blockSize {
			rangeMaskBuf[blockStart+offset] = mask
		}
		encryptAndAccumulate(out.sharedMasks, ctIdx, rangeMaskBuf)
		for offset := range blockSize {
			rangeMaskBuf[blockStart+offset] = 0
		}
	}
	progress.Finish()
	return out
}
