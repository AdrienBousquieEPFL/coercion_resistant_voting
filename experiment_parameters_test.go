package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestExperimentParametersRoundTripAndDeclaredBound(t *testing.T) {
	lit, name := experimentLiteral("refresh-15", "", 50000, 2)
	if lit.PlaintextModulus <= 100000 {
		t.Fatal("plaintext modulus must cover the declared maximum, not a sampled weight sum")
	}
	params, err := bgv.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatal(err)
	}
	manifest := concreteExperimentParameters(name, params)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "parameters.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	roundTrip, gotName := experimentLiteral("ignored", file, 50000, 2)
	got, err := bgv.NewParametersFromLiteral(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	if gotName != name || !slices.Equal(got.Q(), params.Q()) || !slices.Equal(got.P(), params.P()) || got.PlaintextModulus() != params.PlaintextModulus() {
		t.Fatal("parameter-file round trip changed concrete parameters")
	}
	if experimentParameterID(manifest) != experimentParameterID(concreteExperimentParameters(gotName, got)) {
		t.Fatal("parameter identifier changed after round trip")
	}
}

func TestExperimentParametersRejectInsufficientPlaintextRange(t *testing.T) {
	lit, name := experimentLiteral("refresh-15", "", 200, 1)
	params, err := bgv.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "parameters.json")
	data, _ := json.Marshal(concreteExperimentParameters(name, params))
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("accepted plaintext modulus below the declared election bound")
		}
	}()
	experimentLiteral("ignored", file, 500000, 1)
}

func TestWorkloadSeedReplaysInputs(t *testing.T) {
	defer setWorkloadSeed("")
	setWorkloadSeed("comparison-17")
	first := randomVotingVector(25, 5, 5)
	setWorkloadSeed("comparison-17")
	second := randomVotingVector(25, 5, 5)
	if !slices.Equal(first, second) {
		t.Fatal("equal workload seeds produced different inputs")
	}
	setWorkloadSeed("comparison-18")
	if slices.Equal(first, randomVotingVector(25, 5, 5)) {
		t.Fatal("different workload seeds unexpectedly repeated the entire workload")
	}
}
