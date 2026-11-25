package schedule

import (
	"math"
	"testing"
	"time"

	"github.com/1337-llama/quic_research/internal/profile"
)

func jitterSchedule(iv time.Duration, j float64) profile.Schedule {
	return profile.Schedule{Distribution: profile.DistJitter, Interval: profile.Duration(iv), Jitter: j}
}

func TestNewRejectsBadSchedules(t *testing.T) {
	t.Parallel()
	if _, err := New(profile.Schedule{Distribution: "nope", Interval: profile.Duration(time.Second)}, 1); err == nil {
		t.Error("unknown distribution accepted")
	}
	if _, err := New(jitterSchedule(0, 0), 1); err == nil {
		t.Error("zero interval accepted")
	}
}

func TestZeroJitterIsExact(t *testing.T) {
	t.Parallel()
	s, err := New(jitterSchedule(5*time.Second, 0), 42)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if d := s.Next(); d != 5*time.Second {
			t.Fatalf("Next() = %s, want 5s", d)
		}
	}
}

func TestJitterStaysInBoundsAndSpreads(t *testing.T) {
	t.Parallel()
	s, err := New(jitterSchedule(10*time.Second, 0.3), 7)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := s.Bounds()
	if lo != 7*time.Second || hi != 13*time.Second {
		t.Fatalf("Bounds() = %s, %s", lo, hi)
	}
	var minSeen, maxSeen = hi, lo
	var sum float64
	const n = 20000
	for range n {
		d := s.Next()
		if d < lo || d > hi {
			t.Fatalf("Next() = %s outside [%s, %s]", d, lo, hi)
		}
		minSeen, maxSeen = min(minSeen, d), max(maxSeen, d)
		sum += float64(d)
	}
	// The draws should cover most of the range and center on the interval.
	if minSeen > lo+300*time.Millisecond || maxSeen < hi-300*time.Millisecond {
		t.Errorf("draws cover only [%s, %s] of [%s, %s]", minSeen, maxSeen, lo, hi)
	}
	if mean := time.Duration(sum / n); mean < 9900*time.Millisecond || mean > 10100*time.Millisecond {
		t.Errorf("mean = %s, want about 10s", mean)
	}
}

func TestExponentialMeanAndCap(t *testing.T) {
	t.Parallel()
	s, err := New(profile.Schedule{Distribution: profile.DistExponential, Interval: profile.Duration(time.Second)}, 99)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := s.Bounds()
	if lo != MinDelay || hi != MaxExponentialFactor*time.Second {
		t.Fatalf("Bounds() = %s, %s", lo, hi)
	}
	const n = 50000
	var sum, sumSq float64
	for range n {
		d := s.Next()
		if d < lo || d > hi {
			t.Fatalf("Next() = %s outside [%s, %s]", d, lo, hi)
		}
		x := d.Seconds()
		sum += x
		sumSq += x * x
	}
	mean := sum / n
	cv := math.Sqrt(sumSq/n-mean*mean) / mean
	if mean < 0.97 || mean > 1.03 {
		t.Errorf("mean = %.3fs, want about 1s", mean)
	}
	// An exponential distribution has a coefficient of variation of 1. The
	// periodicity detector relies on this being far from a jittered beacon.
	if cv < 0.9 || cv > 1.1 {
		t.Errorf("coefficient of variation = %.3f, want about 1", cv)
	}
}

func TestDeterministicForSeed(t *testing.T) {
	t.Parallel()
	sched := jitterSchedule(time.Minute, 0.5)
	a, _ := New(sched, 1234)
	b, _ := New(sched, 1234)
	c, _ := New(sched, 1235)
	same := true
	for range 50 {
		x, y, z := a.Next(), b.Next(), c.Next()
		if x != y {
			t.Fatalf("same seed diverged: %s vs %s", x, y)
		}
		if x != z {
			same = false
		}
	}
	if same {
		t.Error("different seeds produced identical sequences")
	}
}

func TestMinDelayFloor(t *testing.T) {
	t.Parallel()
	s, err := New(jitterSchedule(time.Microsecond, 0.9), 3)
	if err != nil {
		t.Fatal(err)
	}
	if lo, _ := s.Bounds(); lo != MinDelay {
		t.Errorf("Bounds lo = %s, want %s", lo, MinDelay)
	}
	for range 100 {
		if d := s.Next(); d < MinDelay {
			t.Fatalf("Next() = %s below floor", d)
		}
	}
}
