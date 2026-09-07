package main

import (
	"math/big"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// encryptedPeriodAggregates contains the only persistent ciphertext state
// produced while receiving voter submissions. Individual validity, payload,
// range-mask, and gated-product ciphertexts are transient.
type encryptedPeriodAggregates struct {
	candidateInputs         [][]*rlwe.Ciphertext
	candidateRangeMasks     [][]*rlwe.Ciphertext
	delegationInputs        [][]*rlwe.Ciphertext
	delegationRangeMasks    [][]*rlwe.Ciphertext
	validityCiphertextCount int
	validityCiphertextBytes int64
	aggregateInitWall       time.Duration
	aggregateInitCPU        time.Duration
	clientPreparationWall   time.Duration
	clientPreparationCPU    time.Duration
	serverIngestionWall     time.Duration
	serverIngestionCPU      time.Duration
}

// streamAndAggregatePeriodInputs simulates receiving encrypted voter inputs.
// A voter-period sends at most one encrypted validity bit, which is reused for
// every candidate/delegation payload and range mask present in that submission.
// The input ciphertexts and gated products are discarded immediately after
// they are added to the corresponding period aggregate.
func streamAndAggregatePeriodInputs(
	params bgv.Parameters,
	encoder *bgv.Encoder,
	encryptor *rlwe.Encryptor,
	evaluator *bgv.Evaluator,
	layout packingLayout,
	blockSize, candidateWidth, delegationWidth int,
	candidatePeriods, delegationPeriods [][]int,
	validity [][]uint64,
) encryptedPeriodAggregates {
	periodCount := len(validity)
	assert(periodCount > 0, "validity must contain at least one period")
	voterCount := len(validity[0])
	assert(voterCount > 0, "validity must contain at least one voter")
	assert(len(candidatePeriods) == periodCount, "candidate periods must match validity periods")
	assert(len(delegationPeriods) == periodCount, "delegation periods must match validity periods")

	initWallStart := time.Now()
	initCPUStart := cpuTime()
	zeroSlots := make([]uint64, params.MaxSlots())
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	CountOp("Encode")
	must(encoder.Encode(zeroSlots, ptZero))

	newEncryptedPeriodGrid := func() [][]*rlwe.Ciphertext {
		grid := make([][]*rlwe.Ciphertext, periodCount)
		for period := range periodCount {
			grid[period] = make([]*rlwe.Ciphertext, layout.ciphertextCount)
			for ctIdx := range layout.ciphertextCount {
				CountOp("EncryptNew")
				grid[period][ctIdx] = must1(encryptor.EncryptNew(ptZero))
			}
		}
		return grid
	}

	out := encryptedPeriodAggregates{
		candidateInputs:      newEncryptedPeriodGrid(),
		candidateRangeMasks:  newEncryptedPeriodGrid(),
		delegationInputs:     newEncryptedPeriodGrid(),
		delegationRangeMasks: newEncryptedPeriodGrid(),
	}
	out.aggregateInitWall = time.Since(initWallStart)
	out.aggregateInitCPU = cpuTime() - initCPUStart

	// BFV-style scale-invariant ct*ct multiplication outputs at scale
	// s0*s1/(-Q mod t). Giving e the compensating scale (-Q mod t) makes
	// e*x and e*z return at the ordinary input scale expected by echo.
	qModT := new(big.Int).Mod(params.RingQ().ModulusAtLevel[params.MaxLevel()], new(big.Int).SetUint64(params.PlaintextModulus())).Uint64()
	validityScale := params.NewScale(params.PlaintextModulus() - qModT)
	assert(bgv.MulScaleInvariant(params, validityScale, params.DefaultScale(), params.MaxLevel()).Cmp(params.DefaultScale()) == 0, "validity scale must compensate scale-invariant tensoring")

	validitySlots := make([]uint64, params.MaxSlots())
	ptValidity := bgv.NewPlaintext(params, params.MaxLevel())
	ptValidity.Scale = validityScale
	slotBuf := make([]uint64, params.MaxSlots())
	rangeMaskBuf := make([]uint64, params.MaxSlots())
	ptInput := bgv.NewPlaintext(params, params.MaxLevel())
	inputCount := countPeriodicSubmissions(candidatePeriods) + countPeriodicSubmissions(delegationPeriods)
	progress := NewProgress("4.1-streamed-input-reception-and-validity-gating", int64(2*inputCount))

	encryptValidity := func(bit uint64) *rlwe.Ciphertext {
		wallStart := time.Now()
		cpuStart := cpuTime()
		assert(bit <= 1, "registration validity bit must be boolean")
		for slot := range validitySlots {
			validitySlots[slot] = bit
		}
		CountOp("EncodeValidity")
		must(encoder.Encode(validitySlots, ptValidity))
		CountOp("EncryptValidity")
		ct := must1(encryptor.EncryptNew(ptValidity))
		out.clientPreparationWall += time.Since(wallStart)
		out.clientPreparationCPU += cpuTime() - cpuStart
		out.validityCiphertextCount++
		if out.validityCiphertextBytes == 0 {
			out.validityCiphertextBytes = int64(ct.BinarySize())
		}
		return ct
	}

	encryptGateAndAccumulate := func(dst []*rlwe.Ciphertext, ctIdx int, slots []uint64, validityCt *rlwe.Ciphertext) {
		clientWallStart := time.Now()
		clientCPUStart := cpuTime()
		CountOp("Encode")
		must(encoder.Encode(slots, ptInput))
		CountOp("EncryptNew")
		inputCt := must1(encryptor.EncryptNew(ptInput))
		out.clientPreparationWall += time.Since(clientWallStart)
		out.clientPreparationCPU += cpuTime() - clientCPUStart

		serverWallStart := time.Now()
		serverCPUStart := cpuTime()
		assert(inputCt.Level() == validityCt.Level(), "validity gating operands must start at the same level")
		CountOp("MulRelinNew")
		CountOp("ValidityGate")
		gatedCt := must1(evaluator.MulRelinNew(validityCt, inputCt))
		assert(gatedCt.Level() == inputCt.Level(), "scale-invariant validity gating must preserve the common input level")
		CountOp("Add")
		must(evaluator.Add(dst[ctIdx], gatedCt, dst[ctIdx]))
		out.serverIngestionWall += time.Since(serverWallStart)
		out.serverIngestionCPU += cpuTime() - serverCPUStart
		progress.Inc()
	}

	for period := range periodCount {
		assert(len(candidatePeriods[period]) == voterCount, "candidate period must contain one entry per voter")
		assert(len(delegationPeriods[period]) == voterCount, "delegation period must contain one entry per voter")
		assert(len(validity[period]) == voterCount, "validity period must contain one entry per voter")
		for voter := range voterCount {
			candidateChoice := candidatePeriods[period][voter]
			delegationChoice := delegationPeriods[period][voter]
			if candidateChoice < 0 && delegationChoice < 0 {
				continue
			}

			// This is the sole live reference to the simulated incoming e for
			// this voter-period. Both input types below reuse it.
			validityCt := encryptValidity(validity[period][voter])
			ctIdx := voter / layout.votersPerCiphertext
			localIdx := voter % layout.votersPerCiphertext
			rowInCt := localIdx / layout.votersPerRow
			voterInRow := localIdx % layout.votersPerRow
			blockStart := rowInCt*layout.colsPerCiphertext + voterInRow*blockSize

			if candidateChoice >= 0 {
				assert(candidateChoice < candidateWidth, "candidate choice is outside its logical range")
				slotBuf[blockStart+candidateChoice] = 1
				encryptGateAndAccumulate(out.candidateInputs[period], ctIdx, slotBuf, validityCt)
				slotBuf[blockStart+candidateChoice] = 0

				for offset := range candidateWidth {
					rangeMaskBuf[blockStart+offset] = 1
				}
				encryptGateAndAccumulate(out.candidateRangeMasks[period], ctIdx, rangeMaskBuf, validityCt)
				for offset := range candidateWidth {
					rangeMaskBuf[blockStart+offset] = 0
				}
			}

			if delegationChoice >= 0 {
				assert(delegationChoice < delegationWidth, "delegation choice is outside its logical range")
				slotBuf[blockStart+delegationChoice] = 1
				encryptGateAndAccumulate(out.delegationInputs[period], ctIdx, slotBuf, validityCt)
				slotBuf[blockStart+delegationChoice] = 0

				for offset := range delegationWidth {
					rangeMaskBuf[blockStart+offset] = 1
				}
				encryptGateAndAccumulate(out.delegationRangeMasks[period], ctIdx, rangeMaskBuf, validityCt)
				for offset := range delegationWidth {
					rangeMaskBuf[blockStart+offset] = 0
				}
			}
		}
	}
	progress.Finish()
	return out
}
