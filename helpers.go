package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func must1[T any](v T, err error) T {
	must(err)
	return v
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatal("assertion failed: ", msg)
	}
}

func randUint64n(n uint64) uint64 {
	assert(n > 0, "randUint64n requires n > 0")

	limit := ^uint64(0) - (^uint64(0) % n)
	var buf [8]byte

	for {
		must1(cryptorand.Read(buf[:]))
		x := binary.LittleEndian.Uint64(buf[:])
		if x < limit {
			return x % n
		}
	}
}

func powUint64(base uint64, exp int) uint64 {
	assert(exp >= 0, "exp must be >= 0")
	res := uint64(1)
	for i := 0; i < exp; i++ {
		assert(base == 0 || res <= ^uint64(0)/base, "powUint64 overflow")
		res *= base
	}
	return res
}

func innerProductUint64(w, v []uint64) uint64 {
	assert(len(w) == len(v), "innerProduct: len(w) must equal len(v)")

	var sum uint64
	for i := range w {
		hi, lo := bits.Mul64(w[i], v[i])
		assert(hi == 0, "innerProduct overflow in multiplication")
		var carry uint64
		sum, carry = bits.Add64(sum, lo, 0)
		assert(carry == 0, "innerProduct overflow in accumulation")
	}

	return sum
}

// randomWeightVector samples one weight per voter, then repeats each weight b times
// to obtain a flattened n x b row-major matrix.
func randomWeightVector(n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")

	w := make([]uint64, n)
	if n == 0 {
		return make([]uint64, 0)
	}

	upper := uint64(n)
	for k := 0; k < n; k++ {
		idx := randUint64n(upper)
		w[int(idx)]++
	}

	expanded := make([]uint64, n*b)
	pos := 0
	for i := 0; i < n; i++ {
		for j := 0; j < b; j++ {
			expanded[pos] = w[i]
			pos++
		}
	}

	return expanded
}

// randomVotingVector returns a flattened n x b row-major matrix with one random
// one-hot entry per row.
func randomVotingVector(n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")

	v := make([]uint64, n*b)
	for i := 0; i < n; i++ {
		col := int(randUint64n(uint64(b)))
		v[i*b+col] = 1
	}

	return v
}

// weightedRowSumPlain computes column sums of the element-wise product of two
// flattened n x b matrices (row-major layout).
func weightedRowSumPlain(wFlat, vFlat []uint64, n, b int) []uint64 {
	assert(n >= 0, "n must be >= 0")
	assert(b > 0, "b must be > 0")
	assert(len(wFlat) == n*b, "len(wFlat) must be n*b")
	assert(len(vFlat) == n*b, "len(vFlat) must be n*b")

	out := make([]uint64, b)
	for i := 0; i < n; i++ {
		rowOffset := i * b
		for c := 0; c < b; c++ {
			out[c] += wFlat[rowOffset+c] * vFlat[rowOffset+c]
		}
	}
	return out
}

func ceilDiv(n, d int) int {
	assert(n >= 0, "n must be >= 0")
	assert(d > 0, "d must be > 0")
	if n == 0 {
		return 0
	}
	return 1 + (n-1)/d
}

type packingLayout struct {
	rowsPerCiphertext   int
	colsPerCiphertext   int
	votersPerRow        int
	votersPerCiphertext int
	totalRows           int
	ciphertextCount     int
}

func computePackingLayout(voterCount, candidateCount, rowsPerCiphertext, colsPerCiphertext int) packingLayout {
	assert(voterCount >= 0, "voterCount must be >= 0")
	assert(candidateCount > 0, "candidateCount must be > 0")
	assert(rowsPerCiphertext > 0, "rowsPerCiphertext must be > 0")
	assert(colsPerCiphertext > 0, "colsPerCiphertext must be > 0")

	votersPerRow := colsPerCiphertext / candidateCount
	assert(votersPerRow > 0, "candidateCount must fit at least one voter per row")

	totalRows := ceilDiv(voterCount, votersPerRow)
	return packingLayout{
		rowsPerCiphertext:   rowsPerCiphertext,
		colsPerCiphertext:   colsPerCiphertext,
		votersPerRow:        votersPerRow,
		votersPerCiphertext: rowsPerCiphertext * votersPerRow,
		totalRows:           totalRows,
		ciphertextCount:     ceilDiv(totalRows, rowsPerCiphertext),
	}
}

type opMetric struct {
	name           string
	duration       time.Duration
	totalAllocDiff uint64
	heapAllocDiff  int64
}

type opSummary struct {
	name               string
	calls              int
	totalDuration      time.Duration
	totalAllocDiff     uint64
	totalHeapAllocDiff int64
}

type ciphertextSizeSummary struct {
	name       string
	count      int
	eachBytes  int
	totalBytes int
}

func bytesToMiB(v uint64) float64 {
	return float64(v) / (1024.0 * 1024.0)
}

func bytesToMiBSigned(v int64) float64 {
	return float64(v) / (1024.0 * 1024.0)
}

func measureOperation(name string, op func()) opMetric {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	op()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	return opMetric{
		name:           name,
		duration:       elapsed,
		totalAllocDiff: after.TotalAlloc - before.TotalAlloc,
		heapAllocDiff:  int64(after.Alloc) - int64(before.Alloc),
	}
}

func (s *opSummary) add(m opMetric) {
	if s.name == "" {
		s.name = m.name
	}
	assert(s.name == m.name, "opSummary name mismatch")
	s.calls++
	s.totalDuration += m.duration
	s.totalAllocDiff += m.totalAllocDiff
	s.totalHeapAllocDiff += m.heapAllocDiff
}

func (s opSummary) print() {
	assert(s.calls > 0, "opSummary has no calls")
	fmt.Printf(
		"%-14s calls=%4d total=%10s avg=%10s alloc_total=%8.3f MiB alloc_avg=%8.3f MiB heap_delta_total=%8.3f MiB\n",
		s.name,
		s.calls,
		s.totalDuration,
		s.totalDuration/time.Duration(s.calls),
		bytesToMiB(s.totalAllocDiff),
		bytesToMiB(s.totalAllocDiff/uint64(s.calls)),
		float64(s.totalHeapAllocDiff)/(1024.0*1024.0),
	)
}

func durationMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func summarizeCiphertextSizes(name string, cts []*rlwe.Ciphertext) ciphertextSizeSummary {
	totalBytes := 0
	for _, ct := range cts {
		totalBytes += ct.BinarySize()
	}

	eachSize := 0
	if len(cts) > 0 {
		eachSize = cts[0].BinarySize()
	}

	return ciphertextSizeSummary{
		name,
		len(cts),
		eachSize,
		totalBytes,
	}
}

func printCiphertextSizeTable(rows []ciphertextSizeSummary) {
	fmt.Println("Ciphertext Sizes")
	fmt.Printf("%-14s %7s %15s %15s\n", "Name", "Count", "Each (MiB)", "Total (MiB)")
	for _, row := range rows {
		eachMiB := 0.0
		if row.count > 0 {
			eachMiB = float64(row.eachBytes) / (1024.0 * 1024.0)
		}
		totalMiB := float64(row.totalBytes) / (1024.0 * 1024.0)
		fmt.Printf("%-14s %7d %15.3f %15.3f\n", row.name, row.count, eachMiB, totalMiB)
	}
}

func printOperationMetricsTable(rows []opSummary) {
	fmt.Println("Operation Metrics")
	fmt.Printf(
		"%-14s %7s %12s %12s %18s %16s %18s\n",
		"Operation",
		"Calls",
		"Total ms",
		"Avg ms",
		"Alloc Total (MiB)",
		"Alloc Avg (MiB)",
		"Heap Delta (MiB)",
	)
	for _, row := range rows {
		if row.calls == 0 {
			continue
		}
		fmt.Printf(
			"%-14s %7d %12.3f %12.3f %18.3f %16.3f %18.3f\n",
			row.name,
			row.calls,
			durationMs(row.totalDuration),
			durationMs(row.totalDuration)/float64(row.calls),
			bytesToMiB(row.totalAllocDiff),
			bytesToMiB(row.totalAllocDiff/uint64(row.calls)),
			bytesToMiBSigned(row.totalHeapAllocDiff),
		)
	}
}

func writeMetricsCSV(path string, opRows []opSummary, ctRows []ciphertextSizeSummary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"section",
		"name",
		"calls",
		"total_ms",
		"avg_ms",
		"alloc_total_mib",
		"alloc_avg_mib",
		"heap_delta_total_mib",
		"count",
		"each_bytes",
		"each_mib",
		"total_bytes",
		"total_mib",
	}); err != nil {
		return err
	}

	for _, row := range opRows {
		if row.calls == 0 {
			continue
		}
		if err := w.Write([]string{
			"operation",
			row.name,
			strconv.Itoa(row.calls),
			fmt.Sprintf("%.6f", durationMs(row.totalDuration)),
			fmt.Sprintf("%.6f", durationMs(row.totalDuration)/float64(row.calls)),
			fmt.Sprintf("%.6f", bytesToMiB(row.totalAllocDiff)),
			fmt.Sprintf("%.6f", bytesToMiB(row.totalAllocDiff/uint64(row.calls))),
			fmt.Sprintf("%.6f", bytesToMiBSigned(row.totalHeapAllocDiff)),
			"",
			"",
			"",
			"",
			"",
		}); err != nil {
			return err
		}
	}

	for _, row := range ctRows {
		eachMiB := 0.0
		if row.count > 0 {
			eachMiB = float64(row.eachBytes) / (1024.0 * 1024.0)
		}
		totalMiB := float64(row.totalBytes) / (1024.0 * 1024.0)
		if err := w.Write([]string{
			"ciphertext",
			row.name,
			"",
			"",
			"",
			"",
			"",
			"",
			strconv.Itoa(row.count),
			strconv.Itoa(row.eachBytes),
			fmt.Sprintf("%.6f", eachMiB),
			strconv.Itoa(row.totalBytes),
			fmt.Sprintf("%.6f", totalMiB),
		}); err != nil {
			return err
		}
	}

	if err := w.Error(); err != nil {
		return err
	}

	return nil
}
