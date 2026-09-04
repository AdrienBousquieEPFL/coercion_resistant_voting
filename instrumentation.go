package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// runMeta is serialized to meta.json. It captures every parameter needed to
// reproduce a run and to interpret the other CSVs against fixed inputs.
type runMeta struct {
	RunID               string         `json:"run_id"`
	StartedAt           string         `json:"started_at"`
	N                   int            `json:"n"`
	B                   int            `json:"b"`
	K                   int            `json:"k"`
	T                   int            `json:"T"`
	EchoMode            string         `json:"echo_mode"`
	EchoRefreshInterval int            `json:"echo_refresh_interval"`
	BGV                 *bgvParamsMeta `json:"bgv,omitempty"`
	GitSHA              string         `json:"git_sha"`
	Hostname            string         `json:"hostname"`
	GoVersion           string         `json:"go_version"`
	NumCPU              int            `json:"num_cpu"`
}

// bgvParamsMeta captures the BGV/RLWE parameters chosen for a run. These are
// the inputs needed to reason about both correctness (noise budget) and
// security: the underlying lattice problem is fixed by the ring degree
// N = 2^LogN, the modulus QP, and the secret/error distributions. LogQPBits is
// what you feed a lattice estimator as log2(q) (the keys live mod Q*P).
type bgvParamsMeta struct {
	LogN             int      `json:"logN"` // ring degree N = 2^LogN
	LogQ             []int    `json:"logQ,omitempty"`
	LogP             []int    `json:"logP,omitempty"`
	Q                []uint64 `json:"Q,omitempty"`
	P                []uint64 `json:"P,omitempty"`
	LogQBits         int      `json:"logQ_bits"`  // total ciphertext modulus size = sum(LogQ)
	LogPBits         int      `json:"logP_bits"`  // total special-prime size = sum(LogP)
	LogQPBits        int      `json:"logQP_bits"` // log2(Q*P): the modulus relevant for security
	QLimbs           int      `json:"q_limbs"`    // number of RNS limbs in the Q chain
	PlaintextModulus uint64   `json:"plaintext_modulus"`
	SecretDist       string   `json:"secret_dist"` // Xs
	ErrorDist        string   `json:"error_dist"`  // Xe
}

type phaseRecord struct {
	Name           string
	WallMs         float64
	CPUMs          float64
	HeapStartMiB   float64
	HeapEndMiB     float64
	HeapPeakMiB    float64
	HeapSysPeakMiB float64
	RSSPeakMiB     float64
	GCCount        uint32
}

type objectRecord struct {
	Name      string
	Count     int
	EachBytes int64
	TotalMiB  float64
	Notes     string
}

type sampleRecord struct {
	TMs          int64
	Phase        string
	HeapAllocMiB float64
	HeapSysMiB   float64
	RSSMiB       float64
	// ProcCPUPct is this process's CPU usage over the sampling interval, derived
	// from rusage (user+sys) deltas. It ranges 0..NumCPU*100: 100 means one core
	// fully busy, NumCPU*100 means every core saturated by this process.
	ProcCPUPct float64
	// ProcCoresBusy is ProcCPUPct/100 — the effective number of cores the process
	// kept busy. This is the parallelism signal: a phase pinned near 1.0 on a
	// 14-core box is sequential and a candidate for goroutine parallelisation.
	ProcCoresBusy float64
}

// cpuSampleRecord holds one system-wide per-core utilisation snapshot. Stored in
// long format (one row per core per sample in cpu.csv) so the schema is
// independent of the machine's core count. Unlike ProcCPUPct this is the whole
// machine's view (all processes), which on a shared host includes other load.
type cpuSampleRecord struct {
	TMs     int64
	PerCore []float64 // index = logical core id, value = util% over interval
}

type Phase struct {
	name      string
	startWall time.Time
	startCPU  time.Duration
	startHeap uint64
	startGC   uint32
	startSamp int
}

type metricsRecorder struct {
	mu           sync.Mutex
	runDir       string
	startTime    time.Time
	currentPhase atomic.Value // string
	meta         runMeta
	phases       []phaseRecord
	objects      []objectRecord
	samples      []sampleRecord
	cpuSamples   []cpuSampleRecord
	opCounts     map[string]map[string]int64 // phase -> op -> count
	stop         chan struct{}
	done         chan struct{}
}

var rec *metricsRecorder

// InitMetrics initialises the recorder and starts the background sampler.
// The BGV parameters are filled in later via SetBGVParams, since the
// ParametersLiteral is only constructed during the BGV setup phase.
func InitMetrics(meta runMeta) {
	now := time.Now()
	runID := fmt.Sprintf("%s_n%d_b%d_k%d_T%d",
		now.Format("20060102_150405"), meta.N, meta.B, meta.K, meta.T)
	meta.RunID = runID
	meta.StartedAt = now.Format(time.RFC3339)
	meta.GitSHA = gitSHA()
	meta.Hostname, _ = os.Hostname()
	meta.GoVersion = runtime.Version()
	meta.NumCPU = runtime.NumCPU()

	rec = &metricsRecorder{
		runDir:    filepath.Join("runs", runID),
		startTime: now,
		meta:      meta,
		opCounts:  make(map[string]map[string]int64),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	rec.currentPhase.Store("init")
	fmt.Printf("[metrics] run_id=%s output=%s\n", runID, rec.runDir)

	// Create the run dir up front and write meta.json so even an immediate
	// SIGKILL leaves a discoverable run directory on disk.
	if err := os.MkdirAll(rec.runDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[metrics] could not create run dir %s: %v\n", rec.runDir, err)
	} else {
		_ = writeMeta()
	}

	go rec.sampleLoop(250 * time.Millisecond)
}

// SetBGVParams backfills the chosen BGV parameters into meta. It is called
// once the ParametersLiteral has been constructed (InitMetrics runs before it
// exists). Values are read straight off the literal — i.e. exactly what the
// user chose — and the total modulus sizes are derived for convenience.
func SetBGVParams(p bgv.ParametersLiteral) {
	if rec == nil {
		return
	}
	m := &bgvParamsMeta{
		LogN:             p.LogN,
		LogQ:             append([]int(nil), p.LogQ...),
		LogP:             append([]int(nil), p.LogP...),
		Q:                append([]uint64(nil), p.Q...),
		P:                append([]uint64(nil), p.P...),
		PlaintextModulus: p.PlaintextModulus,
		SecretDist:       describeDistribution(p.Xs),
		ErrorDist:        describeDistribution(p.Xe),
	}
	m.LogQBits = modulusBits(p.LogQ, p.Q)
	m.LogPBits = modulusBits(p.LogP, p.P)
	m.LogQPBits = m.LogQBits + m.LogPBits
	m.QLimbs = max(len(p.LogQ), len(p.Q))
	rec.mu.Lock()
	rec.meta.BGV = m
	rec.mu.Unlock()
}

// modulusBits returns the total bit-length of a modulus described either by
// per-prime bit-sizes (logSizes, the LogQ/LogP option) or by explicit primes
// (primes, the Q/P option). Exactly one of the two is expected to be set.
func modulusBits(logSizes []int, primes []uint64) int {
	total := 0
	for _, s := range logSizes {
		total += s
	}
	if total == 0 {
		for _, q := range primes {
			total += bits.Len64(q)
		}
	}
	return total
}

// describeDistribution renders a ring distribution into a compact, log-friendly
// string, e.g. "Ternary(p=0.6667)" (uniform ternary) or
// "DiscreteGaussian(sigma=3.2, bound=19.2)".
func describeDistribution(d ring.DistributionParameters) string {
	switch v := d.(type) {
	case ring.Ternary:
		if v.H > 0 {
			return fmt.Sprintf("Ternary(H=%d)", v.H)
		}
		return fmt.Sprintf("Ternary(p=%.4g)", v.P)
	case ring.DiscreteGaussian:
		return fmt.Sprintf("DiscreteGaussian(sigma=%.4g, bound=%.4g)", v.Sigma, v.Bound)
	case ring.Uniform:
		return "Uniform"
	case nil:
		return "default"
	default:
		return d.Type()
	}
}

func (r *metricsRecorder) sampleLoop(interval time.Duration) {
	defer close(r.done)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	const flushEvery = 2 * time.Second
	nextFlush := time.Now().Add(flushEvery)

	// Baselines for the process-CPU delta: we measure how much CPU time the
	// process burned between two ticks relative to the wall time elapsed.
	lastCPU := cpuTime()
	lastWall := time.Now()
	// Prime gopsutil's per-core counters so the first real sample reports the
	// delta since loop start rather than since boot. Errors are ignored: per-core
	// stats are best-effort and must never disrupt sampling.
	_, _ = cpu.Percent(0, true)

	for {
		select {
		case <-r.stop:
			return
		case now := <-tick.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			phase, _ := r.currentPhase.Load().(string)

			cpuNow := cpuTime()
			wallDelta := now.Sub(lastWall)
			procCores := 0.0
			if wallDelta > 0 {
				procCores = float64(cpuNow-lastCPU) / float64(wallDelta)
			}
			lastCPU, lastWall = cpuNow, now

			s := sampleRecord{
				TMs:           now.Sub(r.startTime).Milliseconds(),
				Phase:         phase,
				HeapAllocMiB:  bToMiB(ms.HeapAlloc),
				HeapSysMiB:    bToMiB(ms.HeapSys),
				RSSMiB:        currentRSSMiB(),
				ProcCPUPct:    procCores * 100,
				ProcCoresBusy: procCores,
			}
			// System-wide per-core utilisation since the previous call. Best-effort.
			perCore, err := cpu.Percent(0, true)
			r.mu.Lock()
			r.samples = append(r.samples, s)
			if err == nil && len(perCore) > 0 {
				r.cpuSamples = append(r.cpuSamples, cpuSampleRecord{
					TMs:     s.TMs,
					PerCore: perCore,
				})
			}
			r.mu.Unlock()
			if now.After(nextFlush) {
				flushCheckpoint()
				nextFlush = now.Add(flushEvery)
			}
		}
	}
}

// flushCheckpoint writes the current state of every CSV/JSON to disk so a
// SIGKILL or sudden termination leaves the latest known data behind. All
// errors are swallowed and printed to stderr — checkpointing must not panic
// and must not interfere with the main run.
func flushCheckpoint() {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if err := os.MkdirAll(rec.runDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[metrics] checkpoint mkdir failed: %v\n", err)
		return
	}
	for name, fn := range map[string]func() error{
		"meta.json":   writeMeta,
		"phases.csv":  writePhases,
		"objects.csv": writeObjects,
		"samples.csv": writeSamples,
		"cpu.csv":     writeCPU,
		"ops.csv":     writeOps,
	} {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "[metrics] checkpoint %s failed: %v\n", name, err)
		}
	}
}

// currentRSSMiB shells out to ps. ~5 ms cost per call; at 250 ms cadence the
// overhead is ~2% of one core. RSS is the canonical "RAM the OS sees the
// process using", which is the number that matters for OOM analysis.
func currentRSSMiB() float64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0
	}
	rssKB, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return float64(rssKB) / 1024.0
}

// StartPhase forces a GC so heap deltas reflect live data only, then records
// baselines. Pair every call with phase.Stop() to emit a phaseRecord.
func StartPhase(name string) *Phase {
	if rec == nil {
		return &Phase{name: name, startWall: time.Now()}
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rec.currentPhase.Store(name)
	rec.mu.Lock()
	startSamp := len(rec.samples)
	rec.mu.Unlock()
	// Flush so that if the next operation is killed (e.g. SIGKILL during a
	// huge allocation), the on-disk state names the phase that started it.
	flushCheckpoint()
	return &Phase{
		name:      name,
		startWall: time.Now(),
		startCPU:  cpuTime(),
		startHeap: ms.HeapAlloc,
		startGC:   ms.NumGC,
		startSamp: startSamp,
	}
}

func (p *Phase) Stop() {
	if rec == nil {
		return
	}
	wall := time.Since(p.startWall)
	cpu := cpuTime() - p.startCPU
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	heapPeak := bToMiB(ms.HeapAlloc)
	heapSysPeak := bToMiB(ms.HeapSys)
	rssPeak := 0.0
	for i := p.startSamp; i < len(rec.samples); i++ {
		s := rec.samples[i]
		if s.HeapAllocMiB > heapPeak {
			heapPeak = s.HeapAllocMiB
		}
		if s.HeapSysMiB > heapSysPeak {
			heapSysPeak = s.HeapSysMiB
		}
		if s.RSSMiB > rssPeak {
			rssPeak = s.RSSMiB
		}
	}
	rec.phases = append(rec.phases, phaseRecord{
		Name:           p.name,
		WallMs:         msFromDur(wall),
		CPUMs:          msFromDur(cpu),
		HeapStartMiB:   bToMiB(p.startHeap),
		HeapEndMiB:     bToMiB(ms.HeapAlloc),
		HeapPeakMiB:    heapPeak,
		HeapSysPeakMiB: heapSysPeak,
		RSSPeakMiB:     rssPeak,
		GCCount:        ms.NumGC - p.startGC,
	})
	// Release the lock before flushing — flushCheckpoint takes it itself.
	rec.mu.Unlock()
	flushCheckpoint()
	rec.mu.Lock() // re-acquire so the deferred Unlock balances correctly
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// RecordCiphertexts sums BinarySize() across every ciphertext. Levels can
// differ after operations, so we don't extrapolate from cts[0].
func RecordCiphertexts(name string, cts []*rlwe.Ciphertext) {
	if rec == nil || len(cts) == 0 {
		return
	}
	var total int64
	for _, ct := range cts {
		total += int64(ct.BinarySize())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.objects = append(rec.objects, objectRecord{
		Name:      name,
		Count:     len(cts),
		EachBytes: total / int64(len(cts)),
		TotalMiB:  float64(total) / 1024 / 1024,
		Notes:     "each_bytes is mean across slice",
	})
}

func RecordGaloisKeys(name string, keys []*rlwe.GaloisKey) {
	if rec == nil || len(keys) == 0 {
		return
	}
	var total int64
	for _, k := range keys {
		total += int64(k.BinarySize())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.objects = append(rec.objects, objectRecord{
		Name:      name,
		Count:     len(keys),
		EachBytes: total / int64(len(keys)),
		TotalMiB:  float64(total) / 1024 / 1024,
	})
}

func RecordRelinKey(name string, k *rlwe.RelinearizationKey) {
	if rec == nil || k == nil {
		return
	}
	sz := int64(k.BinarySize())
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.objects = append(rec.objects, objectRecord{
		Name:      name,
		Count:     1,
		EachBytes: sz,
		TotalMiB:  float64(sz) / 1024 / 1024,
	})
}

// RecordCrash writes a crash.json into the run directory capturing what the
// recorder knew at the time of an unhandled panic: active phase, elapsed time,
// panic value, and stack trace. Best-effort: errors are swallowed because the
// caller is on a panic path and re-raising would mask the original failure.
func RecordCrash(v any, stack []byte) {
	if rec == nil {
		fmt.Fprintf(os.Stderr, "[metrics] crash before InitMetrics: %v\n%s", v, stack)
		return
	}
	if err := os.MkdirAll(rec.runDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[metrics] could not create run dir %s: %v\n", rec.runDir, err)
		return
	}
	phase, _ := rec.currentPhase.Load().(string)
	rec.mu.Lock()
	completed := make([]string, 0, len(rec.phases))
	for _, p := range rec.phases {
		completed = append(completed, p.Name)
	}
	rec.mu.Unlock()
	crash := map[string]any{
		"occurred_at":      time.Now().Format(time.RFC3339),
		"elapsed_ms":       time.Since(rec.startTime).Milliseconds(),
		"active_phase":     phase,
		"completed_phases": completed,
		"panic":            fmt.Sprintf("%v", v),
		"stack":            string(stack),
	}
	path := filepath.Join(rec.runDir, "crash.json")
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[metrics] could not create %s: %v\n", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(crash); err != nil {
		fmt.Fprintf(os.Stderr, "[metrics] could not write %s: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[metrics] crash recorded in %s (active_phase=%s)\n", path, phase)
}

// CountOp increments the call counter for op under the currently active phase.
// Calls made before the first StartPhase land in the bootstrap "init" bucket.
func CountOp(op string) {
	CountOpN(op, 1)
}

// CountOpN adds n to the call counter for op under the currently active phase.
func CountOpN(op string, n int) {
	if rec == nil || n == 0 {
		return
	}
	phase, _ := rec.currentPhase.Load().(string)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.opCounts[phase] == nil {
		rec.opCounts[phase] = map[string]int64{}
	}
	rec.opCounts[phase][op] += int64(n)
}

// CountPolyEvalOps records a Paterson-Stockmeyer estimate of the underlying
// MulRelinNew and Add operations performed inside polyEval.Evaluate for a
// degree-d polynomial. Counts are filed under "(poly-est)" suffixed names so
// they remain separable from exact op counts.
//
// Cost model (standard PS): ~s baby steps + ~log2(d/s) giant steps +
// ~ceil(d/s) combine muls, with s = ceil(sqrt(d)); ~d additions overall.
// Lattigo's actual implementation differs slightly so treat as ballpark.
func CountPolyEvalOps(degree int) {
	if degree <= 1 {
		return
	}
	s := int(math.Ceil(math.Sqrt(float64(degree))))
	babySteps := s - 1
	giantSteps := 0
	if ratio := float64(degree) / float64(s); ratio > 1 {
		giantSteps = int(math.Ceil(math.Log2(ratio)))
	}
	combine := (degree + s - 1) / s
	muls := babySteps + giantSteps + combine
	adds := degree
	CountOpN("MulRelinNew (poly-est)", muls)
	CountOpN("Add (poly-est)", adds)
}

// RecordSized records a custom object of known live-byte size (e.g. plaintext
// matrices). Excludes Go slice header overhead which is uninteresting noise.
func RecordSized(name string, count int, eachBytes int64, notes string) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.objects = append(rec.objects, objectRecord{
		Name:      name,
		Count:     count,
		EachBytes: eachBytes,
		TotalMiB:  float64(eachBytes*int64(count)) / 1024 / 1024,
		Notes:     notes,
	})
}

func FinalizeMetrics() error {
	if rec == nil {
		return nil
	}
	close(rec.stop)
	<-rec.done
	if err := os.MkdirAll(rec.runDir, 0o755); err != nil {
		return err
	}
	if err := writeMeta(); err != nil {
		return err
	}
	if err := writePhases(); err != nil {
		return err
	}
	if err := writeObjects(); err != nil {
		return err
	}
	if err := writeSamples(); err != nil {
		return err
	}
	if err := writeCPU(); err != nil {
		return err
	}
	if err := writeOps(); err != nil {
		return err
	}
	fmt.Printf("[metrics] wrote phases=%d objects=%d samples=%d ops=%d to %s\n",
		len(rec.phases), len(rec.objects), len(rec.samples), opTotal(), rec.runDir)
	return nil
}

func opTotal() int {
	n := 0
	for _, ops := range rec.opCounts {
		n += len(ops)
	}
	return n
}

func writeMeta() error {
	f, err := os.Create(filepath.Join(rec.runDir, "meta.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(rec.meta)
}

func writePhases() error {
	f, err := os.Create(filepath.Join(rec.runDir, "phases.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"phase", "wall_ms", "cpu_ms",
		"heap_start_mib", "heap_end_mib", "heap_peak_mib",
		"heap_sys_peak_mib", "rss_peak_mib", "gc_count",
	}); err != nil {
		return err
	}
	for _, p := range rec.phases {
		if err := w.Write([]string{
			p.Name,
			f3(p.WallMs), f3(p.CPUMs),
			f3(p.HeapStartMiB), f3(p.HeapEndMiB), f3(p.HeapPeakMiB),
			f3(p.HeapSysPeakMiB), f3(p.RSSPeakMiB),
			strconv.FormatUint(uint64(p.GCCount), 10),
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeObjects() error {
	f, err := os.Create(filepath.Join(rec.runDir, "objects.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"name", "count", "each_bytes", "total_mib", "notes"}); err != nil {
		return err
	}
	for _, o := range rec.objects {
		if err := w.Write([]string{
			o.Name,
			strconv.Itoa(o.Count),
			strconv.FormatInt(o.EachBytes, 10),
			f3(o.TotalMiB),
			o.Notes,
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeOps() error {
	f, err := os.Create(filepath.Join(rec.runDir, "ops.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"phase", "op", "count"}); err != nil {
		return err
	}
	// Order phases by their execution order (rec.phases) so the CSV mirrors the
	// protocol timeline. Any phase missing from rec.phases (e.g. ops counted
	// outside StartPhase) is appended at the end in name order.
	phaseOrder := make([]string, 0, len(rec.opCounts))
	seen := map[string]bool{}
	for _, p := range rec.phases {
		if _, ok := rec.opCounts[p.Name]; ok && !seen[p.Name] {
			phaseOrder = append(phaseOrder, p.Name)
			seen[p.Name] = true
		}
	}
	leftover := make([]string, 0)
	for name := range rec.opCounts {
		if !seen[name] {
			leftover = append(leftover, name)
		}
	}
	sort.Strings(leftover)
	phaseOrder = append(phaseOrder, leftover...)
	for _, phase := range phaseOrder {
		ops := rec.opCounts[phase]
		opNames := make([]string, 0, len(ops))
		for op := range ops {
			opNames = append(opNames, op)
		}
		sort.Strings(opNames)
		for _, op := range opNames {
			if err := w.Write([]string{
				phase, op, strconv.FormatInt(ops[op], 10),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeSamples() error {
	f, err := os.Create(filepath.Join(rec.runDir, "samples.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"t_ms", "phase", "heap_alloc_mib", "heap_sys_mib", "rss_mib",
		"proc_cpu_pct", "proc_cores_busy",
	}); err != nil {
		return err
	}
	for _, s := range rec.samples {
		if err := w.Write([]string{
			strconv.FormatInt(s.TMs, 10),
			s.Phase,
			f3(s.HeapAllocMiB), f3(s.HeapSysMiB), f3(s.RSSMiB),
			f3(s.ProcCPUPct), f3(s.ProcCoresBusy),
		}); err != nil {
			return err
		}
	}
	return nil
}

// writeCPU emits system-wide per-core utilisation in long format: one row per
// (sample, core). Long format keeps the schema independent of how many cores the
// host has, so cpu.csv from a 14-core and a 64-core machine parse identically.
func writeCPU() error {
	f, err := os.Create(filepath.Join(rec.runDir, "cpu.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"t_ms", "core", "util_pct"}); err != nil {
		return err
	}
	for _, s := range rec.cpuSamples {
		for core, pct := range s.PerCore {
			if err := w.Write([]string{
				strconv.FormatInt(s.TMs, 10),
				strconv.Itoa(core),
				f3(pct),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func gitSHA() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func bToMiB(b uint64) float64 { return float64(b) / 1024 / 1024 }
func msFromDur(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
func f3(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
