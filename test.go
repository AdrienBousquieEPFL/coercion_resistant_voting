package main

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func indicatorVectorPlain(values []uint64, T int) []uint64 {
	assert(T > 0, "T must be > 0")

	out := make([]uint64, len(values))
	threshold := uint64(T / 2)
	for i, value := range values {
		if value > threshold {
			out[i] = 1
		}
	}

	return out
}

func delegationIndicatorPlain(wFlat []uint64, n, k, T int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(k > 0, "k must be > 0")
	assert(T > 0, "T must be > 0")
	assert(len(wFlat) == n*k, "len(wFlat) must be n*k")

	out := make([]uint64, n)
	threshold := uint64(T / 2)
	for i := 0; i < n; i++ {
		rowOffset := i * k
		var rowSum uint64
		for l := 0; l < k; l++ {
			if wFlat[rowOffset+l] > threshold {
				rowSum++
			}
		}
		assert(rowSum <= 1, "delegation row indicator sum must be <= 1")
		out[i] = 1 - rowSum
	}

	return out
}

// weightedSelfPowerPlain is the plaintext reference for tally phase 4.5: the boolean
// self-delegation indicator scaled by each voter's own power, dTilde * q. A
// self-delegating voter keeps q[i]; a delegating voter drops to 0.
func weightedSelfPowerPlain(wFlat, q []uint64, n, k, T int) []uint64 {
	assert(len(q) == n, "len(q) must be n")

	out := delegationIndicatorPlain(wFlat, n, k, T)
	for i := range out {
		out[i] *= q[i]
	}

	return out
}

// weightedDelegationIndicatorPlain is the direct plaintext reference for the
// encrypted d' * q_ext product in tally phase 4.4. It preserves the n-by-k row-major
// delegation layout and scales every majority-selected delegation bit by the
// corresponding voter's q[i].
func weightedDelegationIndicatorPlain(wFlat, q []uint64, n, k, T int) []uint64 {
	assert(len(wFlat) == n*k, "len(wFlat) must be n*k")
	assert(len(q) == n, "len(q) must be n")

	out := indicatorVectorPlain(wFlat, T)
	for voter := 0; voter < n; voter++ {
		for delegate := 0; delegate < k; delegate++ {
			out[voter*k+delegate] *= q[voter]
		}
	}

	return out
}

// delegatedVoterWeightsPlain mirrors tally phase 4.6: D * w_d + dTilde. The delegated
// term carries the q-weighted support from phase 4.4, and the self-power term
// the q-weighted dTilde from phase 4.5, so every voter weight is expressed in
// units of voting power.
func delegatedVoterWeightsPlain(D [][]uint64, wFlat, q []uint64, n, k, T int) []uint64 {
	assert(len(D) == n, "len(D) must be n")
	for i := range D {
		assert(len(D[i]) == k, "len(D[i]) must be k")
	}

	dTilde := weightedSelfPowerPlain(wFlat, q, n, k, T)
	delegateSupport := delegateSupportPlain(wFlat, q, n, k, T)

	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = dTilde[i]
		for l := 0; l < k; l++ {
			out[i] += D[i][l] * delegateSupport[l]
		}
	}

	return out
}

// delegateSupportPlain sums the power delegated to each delegate: every voter
// contributes their own power q[i] to the delegate they selected, so this is the
// plaintext reference for the d' * q_ext weighting followed by the rotate-and-add
// reduction in tally phase 4.4.
func delegateSupportPlain(wFlat, q []uint64, n, k, T int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(k > 0, "k must be > 0")
	assert(T > 0, "T must be > 0")
	assert(len(wFlat) == n*k, "len(wFlat) must be n*k")
	assert(len(q) == n, "len(q) must be n")

	out := make([]uint64, k)
	threshold := uint64(T / 2)
	for i := 0; i < n; i++ {
		rowOffset := i * k
		for l := 0; l < k; l++ {
			if wFlat[rowOffset+l] > threshold {
				out[l] += q[i]
			}
		}
	}

	return out
}

func delegatedMaskedTallyPlain(D [][]uint64, wFlat, tFlat, q []uint64, n, b, k, T int) []uint64 {
	assert(len(tFlat) == n*b, "len(tFlat) must be n*b")

	voterWeights := delegatedVoterWeightsPlain(D, wFlat, q, n, k, T)
	out := make([]uint64, b)
	threshold := uint64(T / 2)
	for i := 0; i < n; i++ {
		rowOffset := i * b
		for c := 0; c < b; c++ {
			if tFlat[rowOffset+c] > threshold {
				out[c] += voterWeights[i]
			}
		}
	}

	return out
}

// delegatedMaskedTallyFromPeriodsPlain computes the final plaintext reference
// directly from the period schedules. Unlike delegatedMaskedTallyPlain, it
// never materializes the n*b candidate or n*k delegation echo-total vectors.
// It is used by diagnostic-checks=final to keep those diagnostic allocations
// out of the encrypted tally's live memory.
func delegatedMaskedTallyFromPeriodsPlain(
	D [][]uint64,
	candidatePeriods, delegationPeriods [][]int,
	q []uint64,
	n, b, k, T int,
) []uint64 {
	assert(len(D) == n, "len(D) must be n")
	assert(len(q) == n, "len(q) must be n")
	assert(len(candidatePeriods) == T, "candidate periods must contain T rows")
	assert(len(delegationPeriods) == T, "delegation periods must contain T rows")
	for voter := range n {
		assert(len(D[voter]) == k, "each D row must have k entries")
	}
	for period := range T {
		assert(len(candidatePeriods[period]) == n, "each candidate period must contain n entries")
		assert(len(delegationPeriods[period]) == n, "each delegation period must contain n entries")
	}

	selectedChoice := func(periods, otherPeriods [][]int, voter, width int, counts []uint64) int {
		clear(counts)
		current := -1
		for period := range T {
			choice := periods[period][voter]
			assert(choice >= zeroSubmission && choice < width, "periodic choice is outside its logical range")
			if submissionMask(choice, otherPeriods[period][voter]) == 1 {
				current = choice
			}
			if current >= 0 {
				counts[current]++
			}
		}
		threshold := uint64(T / 2)
		selected := -1
		for choice, count := range counts {
			if count > threshold {
				assert(selected == -1, "echo totals must select at most one choice")
				selected = choice
			}
		}
		return selected
	}

	delegateSupport := make([]uint64, k)
	delegationCounts := make([]uint64, k)
	for voter := range n {
		if delegate := selectedChoice(delegationPeriods, candidatePeriods, voter, k, delegationCounts); delegate >= 0 {
			delegateSupport[delegate] += q[voter]
		}
	}

	out := make([]uint64, b)
	candidateCounts := make([]uint64, b)
	for voter := range n {
		candidate := selectedChoice(candidatePeriods, delegationPeriods, voter, b, candidateCounts)
		if candidate < 0 {
			continue
		}

		weight := uint64(0)
		if selectedChoice(delegationPeriods, candidatePeriods, voter, k, delegationCounts) < 0 {
			weight = q[voter]
		}
		for delegate := range k {
			weight += D[voter][delegate] * delegateSupport[delegate]
		}
		out[candidate] += weight
	}

	return out
}

func decodePackedBlocks(
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	fieldWidth int,
	totalValues int,
	ciphertexts []*rlwe.Ciphertext,
) []uint64 {
	decoded := make([]uint64, 0, totalValues)
	for _, ct := range ciphertexts {
		pt := decryptor.DecryptNew(ct)
		slots := make([]uint64, params.MaxSlots())
		must(encoder.Decode(pt, slots))
		for row := 0; row < layout.rowsPerCiphertext && len(decoded) < totalValues; row++ {
			rowBase := row * layout.colsPerCiphertext
			for voter := 0; voter < layout.votersPerRow && len(decoded) < totalValues; voter++ {
				blockStart := rowBase + voter*blockSize
				decoded = append(decoded, slots[blockStart:blockStart+fieldWidth]...)
			}
		}
	}
	return decoded
}

func verifyIndicatorCiphertexts(
	label string,
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	fieldWidth int,
	values []uint64,
	ciphertexts []*rlwe.Ciphertext,
	T int,
) {
	decoded := decodePackedBlocks(decryptor, encoder, params, layout, blockSize, fieldWidth, len(values), ciphertexts)
	expected := indicatorVectorPlain(values, T)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

func decodeLeadingSlots(
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	slotCount int,
	ciphertext *rlwe.Ciphertext,
) []uint64 {
	pt := decryptor.DecryptNew(ciphertext)
	slots := make([]uint64, params.MaxSlots())
	must(encoder.Decode(pt, slots))
	decoded := append([]uint64(nil), slots[:slotCount]...)
	return decoded
}

func verifyLeadingSlotsCiphertext(
	label string,
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	expected []uint64,
	ciphertext *rlwe.Ciphertext,
) {
	decoded := decodeLeadingSlots(decryptor, encoder, params, len(expected), ciphertext)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

func decodeBaseSlotVector(
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	valueCount int,
	ciphertexts []*rlwe.Ciphertext,
) []uint64 {
	decoded := make([]uint64, 0, valueCount)
	for _, ct := range ciphertexts {
		pt := decryptor.DecryptNew(ct)
		slots := make([]uint64, params.MaxSlots())
		must(encoder.Decode(pt, slots))
		for row := 0; row < layout.rowsPerCiphertext && len(decoded) < valueCount; row++ {
			rowBase := row * layout.colsPerCiphertext
			for voter := 0; voter < layout.votersPerRow && len(decoded) < valueCount; voter++ {
				blockStart := rowBase + voter*blockSize
				decoded = append(decoded, slots[blockStart])
			}
		}
	}
	return decoded
}

func verifyBaseSlotCiphertexts(
	label string,
	decryptor *rlwe.Decryptor,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	expected []uint64,
	ciphertexts []*rlwe.Ciphertext,
) {
	decoded := decodeBaseSlotVector(decryptor, encoder, params, layout, blockSize, len(expected), ciphertexts)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

/****** ADDED FOR MULTIPARY CASE ******/
func mp_decodePackedBlocks(
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	fieldWidth int,
	totalValues int,
	ciphertexts []*rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) []uint64 {
	decoded := make([]uint64, 0, totalValues)
	for _, ct := range ciphertexts {
		pt := thresholdDecrypt(ct, parties, cks, params)
		slots := make([]uint64, params.MaxSlots())
		must(encoder.Decode(pt, slots))
		for row := 0; row < layout.rowsPerCiphertext && len(decoded) < totalValues; row++ {
			rowBase := row * layout.colsPerCiphertext
			for voter := 0; voter < layout.votersPerRow && len(decoded) < totalValues; voter++ {
				blockStart := rowBase + voter*blockSize
				decoded = append(decoded, slots[blockStart:blockStart+fieldWidth]...)
			}
		}
	}
	return decoded
}

func mp_verifyIndicatorCiphertexts(
	label string,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	fieldWidth int,
	values []uint64,
	ciphertexts []*rlwe.Ciphertext,
	T int,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) {
	decoded := mp_decodePackedBlocks(encoder, params, layout, blockSize, fieldWidth, len(values), ciphertexts, cks, parties)
	expected := indicatorVectorPlain(values, T)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

func mp_verifyPackedCiphertexts(
	label string,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	fieldWidth int,
	expected []uint64,
	ciphertexts []*rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) {
	decoded := mp_decodePackedBlocks(encoder, params, layout, blockSize, fieldWidth, len(expected), ciphertexts, cks, parties)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

func mp_decodeLeadingSlots(
	encoder *bgv.Encoder,
	params bgv.Parameters,
	slotCount int,
	ciphertext *rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) []uint64 {
	pt := thresholdDecrypt(ciphertext, parties, cks, params)
	slots := make([]uint64, params.MaxSlots())
	must(encoder.Decode(pt, slots))
	decoded := append([]uint64(nil), slots[:slotCount]...)
	return decoded
}

func mp_verifyLeadingSlotsCiphertext(
	label string,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	expected []uint64,
	ciphertext *rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) {
	decoded := mp_decodeLeadingSlots(encoder, params, len(expected), ciphertext, cks, parties)
	verifyLeadingSlots(label, expected, decoded)
}

func verifyLeadingSlots(label string, expected, decoded []uint64) {
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}

func mp_decodeBaseSlotVector(
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	valueCount int,
	ciphertexts []*rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) []uint64 {
	decoded := make([]uint64, 0, valueCount)
	for _, ct := range ciphertexts {
		pt := thresholdDecrypt(ct, parties, cks, params)
		slots := make([]uint64, params.MaxSlots())
		must(encoder.Decode(pt, slots))
		for row := 0; row < layout.rowsPerCiphertext && len(decoded) < valueCount; row++ {
			rowBase := row * layout.colsPerCiphertext
			for voter := 0; voter < layout.votersPerRow && len(decoded) < valueCount; voter++ {
				blockStart := rowBase + voter*blockSize
				decoded = append(decoded, slots[blockStart])
			}
		}
	}
	return decoded
}

func mp_verifyBaseSlotCiphertexts(
	label string,
	encoder *bgv.Encoder,
	params bgv.Parameters,
	layout packingLayout,
	blockSize int,
	expected []uint64,
	ciphertexts []*rlwe.Ciphertext,
	cks *multiparty.KeySwitchProtocol,
	parties []party,
) {
	decoded := mp_decodeBaseSlotVector(encoder, params, layout, blockSize, len(expected), ciphertexts, cks, parties)
	assert(len(decoded) == len(expected), fmt.Sprintf("%s length mismatch: expected %d, got %d", label, len(expected), len(decoded)))
	for i := range expected {
		assert(decoded[i] == expected[i], fmt.Sprintf("%s mismatch at index %d: expected %d, got %d", label, i, expected[i], decoded[i]))
	}
	log.Printf("ASSERT PASSED: %s", label)
}
