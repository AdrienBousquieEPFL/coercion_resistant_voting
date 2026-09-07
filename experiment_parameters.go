package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Parameter files are experiment inputs, with decimal-string primes so readers
// using floating-point JSON numbers cannot silently round the RNS moduli.
type experimentParameters struct {
	SchemaVersion    int      `json:"schema_version"`
	Name             string   `json:"name"`
	Lattigo          string   `json:"lattigo_version"`
	LogN             int      `json:"logN"`
	Q                []string `json:"Q"`
	P                []string `json:"P"`
	PlaintextModulus uint64   `json:"plaintext_modulus"`
}

func experimentLiteral(profile, filename string, n, qmax int) (bgv.ParametersLiteral, string) {
	assert(n > 0 && qmax > 0, "n and qmax must be positive")
	assert(uint64(n) <= (^uint64(0)-1)/uint64(qmax), "n*qmax+1 overflows")
	bound := uint64(n) * uint64(qmax)
	lit := bgv.ParametersLiteral{Xs: ring.Ternary{P: 2.0 / 3.0}, Xe: ring.DiscreteGaussian{Sigma: rlwe.DefaultNoise, Bound: rlwe.DefaultNoiseBound}}
	if filename != "" {
		var p experimentParameters
		must(json.Unmarshal(must1(os.ReadFile(filename)), &p))
		assert(p.SchemaVersion == 1 && p.Lattigo == "v6.2.0", "unsupported parameter schema or Lattigo version")
		assert(p.Name != "" && len(p.Q) >= 4 && len(p.P) > 0, "parameter file needs a name, at least four Q primes, and P")
		lit.LogN, lit.PlaintextModulus = p.LogN, p.PlaintextModulus
		for _, q := range p.Q {
			lit.Q = append(lit.Q, must1(strconv.ParseUint(q, 10, 64)))
		}
		for _, p := range p.P {
			lit.P = append(lit.P, must1(strconv.ParseUint(p, 10, 64)))
		}
		assert(lit.PlaintextModulus > bound, "parameter plaintext modulus does not cover n*qmax")
		return lit, p.Name
	}
	switch profile {
	case "legacy":
		lit.LogN, lit.LogQ, lit.LogP = 14, []int{55, 46, 46, 46, 46, 46, 46, 46}, []int{61}
	case "refresh-14":
		lit.LogN, lit.LogQ, lit.LogP = 14, []int{52, 52, 52, 52, 52, 52}, []int{40}
	case "refresh-15":
		lit.LogN, lit.LogQ, lit.LogP = 15, []int{60, 60, 60, 60, 60, 60}, []int{61}
	case "refresh-wide-15":
		lit.LogN, lit.LogQ, lit.LogP = 15, []int{60, 60, 60, 60, 60, 60, 60}, []int{61}
	case "tree-none-15":
		lit.LogN, lit.LogQ, lit.LogP = 15, []int{60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, []int{61}
	default:
		panic(fmt.Sprintf("unknown parameter profile %q", profile))
	}
	lit.PlaintextModulus = pickPlaintextModulus(bound+1, lit.LogN)
	return lit, profile
}

func concreteExperimentParameters(name string, params bgv.Parameters) experimentParameters {
	p := experimentParameters{SchemaVersion: 1, Name: name, Lattigo: "v6.2.0", LogN: params.LogN(), PlaintextModulus: params.PlaintextModulus()}
	for _, q := range params.Q() {
		p.Q = append(p.Q, strconv.FormatUint(q, 10))
	}
	for _, q := range params.P() {
		p.P = append(p.P, strconv.FormatUint(q, 10))
	}
	return p
}

func experimentParameterID(p experimentParameters) string {
	// The identifier covers the canonical Go JSON representation, including name.
	digest := sha256.Sum256(must1(json.Marshal(p)))
	return hex.EncodeToString(digest[:])
}
