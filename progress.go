package main

import (
	fmt "fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// progressEnabled gates all progress rendering. It is set from the -progress
// CLI flag in main and left true by default. Rendering always goes to stderr so
// it never pollutes the stdout results/metrics output that downstream tooling
// parses.
var progressEnabled = true

// stderrIsTTY reports whether stderr is an interactive terminal. On a TTY we
// redraw a single line in place with '\r'; otherwise (piped to a file or CI
// log) we emit occasional newline-terminated updates so the log stays readable.
var stderrIsTTY = func() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}()

// Progress is a tqdm-style progress bar for a loop with a known total. Workers
// call Inc/Add (safe for concurrent use); a background goroutine repaints the
// bar on a fixed cadence so the hot loop never blocks on I/O.
type Progress struct {
	label string
	total int64
	count atomic.Int64
	start time.Time

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	lastPctLogged int64 // non-TTY only: last decile already printed
}

// NewProgress starts a progress bar labelled `label` tracking `total` units of
// work. Pair every call with Finish(). When progress is disabled it returns a
// no-op bar so call sites stay unconditional.
func NewProgress(label string, total int64) *Progress {
	p := &Progress{
		label:         label,
		total:         total,
		start:         time.Now(),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		lastPctLogged: -1,
	}
	if !progressEnabled || total <= 0 {
		close(p.done)
		return p
	}
	go p.renderLoop(100 * time.Millisecond)
	return p
}

// Inc adds one completed unit of work.
func (p *Progress) Inc() { p.count.Add(1) }

// Add adds n completed units of work.
func (p *Progress) Add(n int64) { p.count.Add(n) }

func (p *Progress) renderLoop(interval time.Duration) {
	defer close(p.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.render(p.count.Load(), false)
		}
	}
}

// Finish stops the renderer, paints the final 100% state and moves to a new
// line. Safe to call more than once.
func (p *Progress) Finish() {
	p.stopOnce.Do(func() {
		close(p.stop)
		<-p.done
		if progressEnabled && p.total > 0 {
			p.render(p.total, true)
			fmt.Fprintln(os.Stderr)
		}
	})
}

func (p *Progress) render(cur int64, final bool) {
	cur = min(cur, p.total)
	elapsed := time.Since(p.start)
	frac := float64(cur) / float64(p.total)
	pct := int(frac * 100)

	if !stderrIsTTY {
		// Log at each new decile (and at completion) to avoid spamming a file.
		decile := int64(pct / 10)
		if !final && decile <= p.lastPctLogged {
			return
		}
		p.lastPctLogged = decile
		fmt.Fprintf(os.Stderr, "[progress] %s %3d%% (%d/%d) elapsed=%s%s\n",
			p.label, pct, cur, p.total, fmtDur(elapsed), etaSuffix(cur, p.total, elapsed))
		return
	}

	const barWidth = 30
	filled := min(int(frac*barWidth), barWidth)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	rate := float64(cur) / elapsed.Seconds()
	fmt.Fprintf(os.Stderr, "\r%s |%s| %3d%% %d/%d [%s%s, %.0f it/s]\033[K",
		p.label, bar, pct, cur, p.total, fmtDur(elapsed),
		etaSuffix(cur, p.total, elapsed), rate)
}

// Spinner is an indeterminate progress indicator for a single long-running call
// whose internal progress cannot be observed (e.g. Galois key generation). It
// animates a spinner with the elapsed time until Finish is called.
type Spinner struct {
	label    string
	start    time.Time
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// NewSpinner starts an animated spinner labelled `label`. Pair with Finish().
func NewSpinner(label string) *Spinner {
	s := &Spinner{
		label: label,
		start: time.Now(),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	if !progressEnabled {
		close(s.done)
		return s
	}
	go s.spinLoop(120 * time.Millisecond)
	return s
}

func (s *Spinner) spinLoop(interval time.Duration) {
	defer close(s.done)
	frames := []rune(`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if stderrIsTTY {
				fmt.Fprintf(os.Stderr, "\r%c %s [%s]\033[K",
					frames[i%len(frames)], s.label, fmtDur(time.Since(s.start)))
			}
			i++
		}
	}
}

// Finish stops the spinner and prints the total elapsed time. Safe to call more
// than once.
func (s *Spinner) Finish() {
	s.stopOnce.Do(func() {
		close(s.stop)
		<-s.done
		if !progressEnabled {
			return
		}
		elapsed := fmtDur(time.Since(s.start))
		if stderrIsTTY {
			fmt.Fprintf(os.Stderr, "\r✓ %s [%s]\033[K\n", s.label, elapsed)
		} else {
			fmt.Fprintf(os.Stderr, "[progress] %s done [%s]\n", s.label, elapsed)
		}
	})
}

func etaSuffix(cur, total int64, elapsed time.Duration) string {
	if cur <= 0 || cur >= total {
		return ""
	}
	remaining := time.Duration(float64(elapsed) * float64(total-cur) / float64(cur))
	return ", ETA " + fmtDur(remaining)
}

// fmtDur renders a duration compactly as e.g. "1m05s" or "12.3s".
func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%dm%02ds", m, s)
}
