package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"

	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type party struct {
	sk         *rlwe.SecretKey // secret key of the party
	rlkEphemSk *rlwe.SecretKey // ephemeral state to be used in the RKG protocol

	input []uint64 // the input of the party, encoding a set as a binary vector
}

var l = log.New(os.Stderr, "", 0)

func thresholdDecrypt(
	ct *rlwe.Ciphertext,
	parties []party,
	cks *multiparty.KeySwitchProtocol,
	params bgv.Parameters,
) *rlwe.Plaintext {

	level := ct.Level()

	zero := rlwe.NewSecretKey(params)

	// One share per party
	shares := make([]multiparty.KeySwitchShare, len(parties))

	for i := range parties {

		shares[i] = cks.AllocateShare(level)

		cks.GenShare(
			parties[i].sk,
			zero,
			ct,
			&shares[i],
		)
	}

	// Aggregate shares
	combined := cks.AllocateShare(level)

	for i := range shares {

		cks.AggregateShares(
			combined,
			shares[i],
			&combined,
		)
	}

	// Key-switch to zero key
	out := rlwe.NewCiphertext(params, 1, level)

	cks.KeySwitch(
		ct,
		combined,
		out,
	)

	// Extract plaintext from c0
	pt := bgv.NewPlaintext(params, level)

	// Preserve scale, NTT state, batching information, dimensions, etc.
	*pt.MetaData = *out.MetaData

	// Copy into the polynomial allocated by NewPlaintext.
	pt.Value.CopyLvl(level, out.Value[0])

	return pt
}

// collectiveRefresh executes Lattigo's multiparty BGV refresh protocol under
// the same collective secret key. It restores a correctly decrypting
// ciphertext to the maximum Q level without reconstructing its plaintext at
// the tallying party.
//
// params.Xe() matches the noise distribution used by the current prototype and
// Lattigo's mpbgv refresh tests. A deployment must choose the protocol's noise-
// flooding distribution as part of its concrete multiparty security analysis.
func collectiveRefresh(
	ct *rlwe.Ciphertext,
	parties []party,
	params bgv.Parameters,
	crs sampling.PRNG,
) *rlwe.Ciphertext {
	assert(len(parties) > 0, "collective refresh requires at least one party")

	refresh := must1(mpbgv.NewRefreshProtocol(params, params.Xe()))
	inputLevel := ct.Level()
	outputLevel := params.MaxLevel()
	crp := refresh.SampleCRP(outputLevel, crs)

	shares := make([]multiparty.RefreshShare, len(parties))
	for i := range parties {
		shares[i] = refresh.AllocateShare(inputLevel, outputLevel)
		CountOp("RefreshGenShare")
		must(refresh.GenShare(parties[i].sk, ct, crp, &shares[i]))
	}

	combined := shares[0]
	for i := 1; i < len(shares); i++ {
		CountOp("RefreshAggregateShare")
		must(refresh.AggregateShares(shares[i], combined, &combined))
	}

	out := bgv.NewCiphertext(params, 1, outputLevel)
	*out.MetaData = *ct.MetaData
	CountOp("RefreshFinalize")
	must(refresh.Finalize(ct, crp, combined, out))
	assert(out.Level() == outputLevel, "collective refresh must restore the maximum level")
	return out
}

func genparties(params bgv.Parameters, N int) []party {

	// Create the parties and generates a secret key for each party
	P := make([]party, N)
	for i := range P {
		P[i].sk = rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	}

	return P
}

func execCKGProtocol(params bgv.Parameters, crs sampling.PRNG, P []party) *rlwe.PublicKey {

	l.Println("> Public Enryption Key Generation")

	// Creates a protocol type for the collective public key generation.
	// The type is stateless and can be used to generate as many public keys as needed.
	ckg := multiparty.NewPublicKeyGenProtocol(params)

	// Allocates the memory for the parties' shares in the protocol
	ckgShares := make([]multiparty.PublicKeyGenShare, len(P))
	for i := range ckgShares {
		ckgShares[i] = ckg.AllocateShare()
	}
	ckgCombined := ckg.AllocateShare() // Allocate the memory for the combined share

	// sample the common reference polynomial (crp) from the common reference string (crs)
	crp := ckg.SampleCRP(crs)

	// Generate the parties' shares
	elapsedCKGParty = runTimedParty(func() {
		for i, pi := range P {
			ckg.GenShare(pi.sk, crp, &ckgShares[i])
		}
	}, len(P))

	// Aggregate the parties' shares into a collective public key
	pk := rlwe.NewPublicKey(params)
	elapsedCKGCloud = runTimed(func() {
		// Aggregate the parties' shares into a combined share
		for i := range P {
			ckg.AggregateShares(ckgShares[i], ckgCombined, &ckgCombined)
		}

		// Generate the public key from the combined share
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func execRKGProtocol(params bgv.Parameters, crs sampling.PRNG, P []party) *rlwe.RelinearizationKey {

	l.Println("> Relinearization Key Generation")

	// Creates a protocol type for the collective relinearization key generation.
	// The type is stateless and can be used to generate as many relinearization keys as needed.
	// The RKG protocol has two rounds.
	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)

	// Allocates the memory for the parties' shares in the protocol
	rkgSharesRoundOne := make([]multiparty.RelinearizationKeyGenShare, len(P))
	rkgSharesRoundTwo := make([]multiparty.RelinearizationKeyGenShare, len(P))
	for i := range P {
		P[i].rlkEphemSk, rkgSharesRoundOne[i], rkgSharesRoundTwo[i] = rkg.AllocateShare()
		// the parties have a private ephemeral secret key in the RKGen protocol
	}
	// Allocate the memory for the combined public shares
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	// Sample the common reference polynomial (crp) from the common reference string (crs)
	crp := rkg.SampleCRP(crs)

	// The parties generate their shares for round one
	elapsedRKGParty = runTimedParty(func() {
		for i, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, &rkgSharesRoundOne[i])
		}
	}, len(P))

	// the helper aggregates the parties' shares for round one
	elapsedRKGCloud = runTimed(func() {
		for i := range P {
			rkg.AggregateShares(rkgSharesRoundOne[i], rkgCombined1, &rkgCombined1)
		}
	})

	// The parties generate their shares for round two
	elapsedRKGParty += runTimedParty(func() {
		for i, pi := range P {
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, &rkgSharesRoundTwo[i])
		}
	}, len(P))

	// the helper aggregates the parties' shares for round two and generates the relinearization key
	rlk := rlwe.NewRelinearizationKey(params)
	elapsedRKGCloud += runTimed(func() {
		for i := range P {
			rkg.AggregateShares(rkgSharesRoundTwo[i], rkgCombined2, &rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}

// func execGTGProtocol(params bgv.Parameters, crs sampling.PRNG, galEls []uint64, participants []party) (galKeys []*rlwe.GaloisKey) {

// 	l.Println("> Galois Automorphism-Keys Generation")

// 	// Creates a protocol type for the collective galois key generation.
// 	// The type is stateless and can be used to generate as many galois keys as needed.
// 	gkg := multiparty.NewGaloisKeyGenProtocol(params) // Rotation keys generation

// 	var elapsedGKGCloud time.Duration
// 	var elapsedGKGParty time.Duration

// 	// Allocates the memory for the parties' shares in the protocol
// 	gkgShares := make([]multiparty.GaloisKeyGenShare, len(participants))
// 	tsks := make([]*rlwe.SecretKey, len(participants))
// 	for i := range participants {
// 		gkgShares[i] = gkg.AllocateShare()
// 		tsks[i] = rlwe.NewSecretKey(params)
// 	}

// 	// Allocate a slice for storing the output keys
// 	galKeys = make([]*rlwe.GaloisKey, len(galEls))

// 	// Runs the GKG protocol for each required Galois key
// 	// Note: this demo re-uses the allocated shares for each execution.
// 	for j, galEl := range galEls {

// 		// Sample the common reference polynomial (crp) common reference string (crs)
// 		crp := gkg.SampleCRP(crs)

// 		// The parties generate their shares for the Galois key generation protocol
// 		elapsedGKGParty += runTimedParty(func() {
// 			for i, pi := range participants {
// 				// Generate the t-out-of-t secret key of the party within the group of participants
// 				err := pi.Combiner.GenAdditiveShare(getShamirPoints(participants), pi.shamirPt, pi.tsk, tsks[i])
// 				check(err)

// 				// Generate the shares for the Galois key generation protocol from the t-out-of-t secret key
// 				err = gkg.GenShare(tsks[i], galEl, crp, &gkgShares[i])
// 				check(err)
// 			}

// 		}, len(participants))

// 		// The helper aggregates the parties' shares and generates the Galois key
// 		elapsedGKGCloud += runTimed(func() {

// 			gkgShareCombined := gkg.AllocateShare() // Allocate the memory for the combined share
// 			gkgShareCombined.GaloisElement = galEl
// 			for i := range participants {
// 				err := gkg.AggregateShares(gkgShares[i], gkgShareCombined, &gkgShareCombined)
// 				check(err)
// 			}

// 			galKeys[j] = rlwe.NewGaloisKey(params)

// 			if err := gkg.GenGaloisKey(gkgShareCombined, crp, galKeys[j]); err != nil {
// 				panic(err)
// 			}
// 		})
// 	}
// 	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedGKGCloud, elapsedGKGParty)

// 	return
// }

func execGKGProtocol(
	params bgv.Parameters,
	crs sampling.PRNG,
	P []party,
	galEls []uint64,
	evkParams rlwe.EvaluationKeyParameters,
) []*rlwe.GaloisKey {

	l.Println("> Galois Key Generation")
	fmt.Println(galEls)

	// Creates the collective Galois-key-generation protocol.
	// The protocol is stateless and reusable.
	gkg := multiparty.NewGaloisKeyGenProtocol(params)

	// Output keys
	gks := make([]*rlwe.GaloisKey, len(galEls))

	// Timing accumulators
	var elapsedGKGCloud time.Duration
	var elapsedGKGParty time.Duration

	// One Galois key per Galois element
	for galElIdx, galEl := range galEls {

		// Allocate one share per party
		shares := make([]multiparty.GaloisKeyGenShare, len(P))

		for i := range P {
			shares[i] = gkg.AllocateShare()
		}

		// Combined share
		combined := gkg.AllocateShare()
		combined.GaloisElement = galEl

		// Common random polynomial
		crp := gkg.SampleCRP(crs)

		// Each party generates a share
		elapsedGKGParty += runTimedParty(func() {

			for i, pi := range P {

				gkg.GenShare(
					pi.sk,
					galEl,
					crp,
					&shares[i],
				)
			}

		}, len(P))

		// Aggregate shares
		elapsedGKGCloud += runTimed(func() {

			for i := range P {

				gkg.AggregateShares(
					shares[i],
					combined,
					&combined,
				)
			}

		})

		// Finalize Galois key
		gks[galElIdx] = rlwe.NewGaloisKey(params, evkParams)

		elapsedGKGCloud += runTimed(func() {

			gkg.GenGaloisKey(
				combined,
				crp,
				gks[galElIdx],
			)

		})
	}

	l.Printf(
		"\tdone (cloud: %s, party: %s)\n",
		elapsedGKGCloud,
		elapsedGKGParty,
	)

	return gks
}

var (
	elapsedEncryptParty,
	elapsedEncryptCloud,
	elapsedCKGCloud,
	elapsedCKGParty,
	elapsedRKGCloud,
	elapsedRKGParty,
	elapsedPCKSCloud,
	elapsedPCKSParty,
	elapsedEvalCloudCPU,
	elapsedEvalCloud,
	elapsedEvalParty time.Duration
)

func check(err error) {
	if err != nil {
		l.Fatal(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}
