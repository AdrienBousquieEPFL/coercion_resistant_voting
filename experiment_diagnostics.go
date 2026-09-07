package main

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

var workloadRandom io.Reader = cryptorand.Reader

func setWorkloadSeed(seed string) {
	workloadRandom = cryptorand.Reader
	if seed != "" {
		digest := sha256.Sum256([]byte("voting-benchmark/workload/v1/" + seed))
		workloadRandom = must1(sampling.NewKeyedPRNG(digest[:]))
	}
}

type noiseDiagnostics struct {
	params    bgv.Parameters
	encoder   *bgv.Encoder
	evaluator *bgv.Evaluator
	decryptor *rlwe.Decryptor
	file      *os.File
	writer    *csv.Writer
	minimum   float64
}

var noiseChecks *noiseDiagnostics

// This diagnostic is opt-in and only uses synthetic experiment keys. It
// reconstructs the test secret in memory, never serializes it, and must not
// run during timing measurements. Independent plaintext checks remain enabled.
func startNoiseDiagnostics(params bgv.Parameters, encoder *bgv.Encoder, evaluator *bgv.Evaluator, parties []party, minimum float64) {
	sk := rlwe.NewSecretKey(params)
	for _, p := range parties {
		params.RingQP().Add(sk.Value, p.sk.Value, sk.Value)
	}
	f := must1(os.OpenFile(filepath.Join(rec.runDir, "noise.csv"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	w := csv.NewWriter(f)
	must(w.Write([]string{"checkpoint", "index", "level", "std_bits", "max_bits", "margin_bits"}))
	noiseChecks = &noiseDiagnostics{params, encoder, evaluator, bgv.NewDecryptor(params, sk), f, w, minimum}
}

func finishNoiseDiagnostics() {
	if noiseChecks != nil {
		noiseChecks.writer.Flush()
		must(noiseChecks.writer.Error())
		must(noiseChecks.file.Close())
		noiseChecks = nil
	}
}

func recordNoiseCheckpoint(name string, cts []*rlwe.Ciphertext) {
	d := noiseChecks
	if d == nil {
		return
	}
	for i, ct := range cts {
		values := make([]uint64, d.params.MaxSlots())
		must(d.encoder.Decode(d.decryptor.DecryptNew(ct), values))
		pt := bgv.NewPlaintext(d.params, ct.Level())
		pt.MetaData = ct.MetaData.CopyNew()
		must(d.encoder.Encode(values, pt))
		residual := must1(d.evaluator.SubNew(ct, pt))
		std, _, maxNoise := rlwe.Norm(residual, d.decryptor)
		logQ := 0.0
		for _, q := range d.params.Q()[:ct.Level()+1] {
			logQ += math.Log2(float64(q))
		}
		margin := logQ - 1 - math.Log2(float64(d.params.PlaintextModulus())) - maxNoise
		must(d.writer.Write([]string{name, strconv.Itoa(i), strconv.Itoa(ct.Level()), fmt.Sprintf("%.6f", std), fmt.Sprintf("%.6f", maxNoise), fmt.Sprintf("%.6f", margin)}))
		d.writer.Flush()
		must(d.writer.Error())
		assert(!math.IsNaN(margin) && margin >= d.minimum, fmt.Sprintf("noise margin at %s[%d]: %.3f < %.3f bits", name, i, margin, d.minimum))
	}
}
