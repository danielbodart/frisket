package grant

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

type clock struct{ t time.Duration }

func (c *clock) now() time.Duration { return c.t }

var github = Key{Anchor: Anchor{Pid: 5113, Start: 21894930}, Host: "SHA256:host", KeyFP: "SHA256:key"}

func TestAGrantEndsAtTheAnswerPlusTheChoiceAndUseNeverExtendsIt(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	g.Grant(github, c.t+15*time.Minute)
	for range 14 {
		c.t += time.Minute
		if !g.Use(github) {
			t.Fatalf("no grant %v after the answer", c.t-time.Hour)
		}
	}
	c.t += time.Minute
	if g.Use(github) {
		t.Error("the grant outlived its 15 minutes")
	}

	g.Grant(github, c.t+10*time.Minute)
	g.Grant(github, c.t+5*time.Minute)
	c.t += 7 * time.Minute
	if !g.Use(github) {
		t.Error("a shorter second grant cut the first short")
	}
}

func TestAGrantEndsAtItsTimeWhateverTheUses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c := &clock{t: time.Duration(rapid.Int64Range(0, 1<<50).Draw(t, "answer"))}
		g := newWithClock(c.now)
		end := c.t + time.Duration(rapid.Int64Range(1, int64(24*time.Hour)).Draw(t, "chosen"))
		g.Grant(github, end)
		for _, step := range rapid.SliceOf(rapid.Int64Range(0, int64(time.Hour))).Draw(t, "steps") {
			c.t += time.Duration(step)
			if got, want := g.Use(github), c.t < end; got != want {
				t.Fatalf("Use at %v = %v, grant ends at %v", c.t, got, end)
			}
		}
	})
}

func TestAGrantDoesNotSurviveASuspendLongerThanItsTime(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	g.Grant(github, c.t+15*time.Minute)
	c.t += 2 * time.Hour
	if g.Use(github) {
		t.Error("the grant survived a two-hour suspend")
	}
	if a, b := Now(), Now(); b < a || a == 0 {
		t.Errorf("CLOCK_BOOTTIME read %v then %v", a, b)
	}
}

func TestAGrantForADeadAnchorNeverMatchesAReusedPid(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	g.Grant(github, c.t+time.Hour)
	reused := github
	reused.Anchor.Start++
	if g.Use(reused) {
		t.Error("a reused pid matched the dead anchor's grant")
	}
}

func TestAGrantCoversOnlyItsOwnKey(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	g.Grant(github, c.t+time.Hour)
	for name, k := range map[string]Key{
		"another host":   {Anchor: github.Anchor, Host: "SHA256:other", KeyFP: github.KeyFP},
		"another key":    {Anchor: github.Anchor, Host: github.Host, KeyFP: "SHA256:other"},
		"another anchor": {Anchor: Anchor{Pid: 5114, Start: github.Anchor.Start}, Host: github.Host, KeyFP: github.KeyFP},
		"forwarded":      {Anchor: github.Anchor, Host: github.Host, KeyFP: github.KeyFP, Fwd: true},
	} {
		if g.Use(k) {
			t.Errorf("a direct grant covers %s", name)
		}
	}
}

func TestANewGrantWakesTheWaitingRows(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	waiting := g.Changed()
	select {
	case <-waiting:
		t.Fatal("woken before any grant")
	default:
	}
	g.Grant(github, c.t+time.Minute)
	select {
	case <-waiting:
	default:
		t.Fatal("a new grant did not wake the waiting rows")
	}
	if g.Changed() == waiting {
		t.Error("the next wait is on the closed channel")
	}
}

func TestAGrantDropsExpiredEntries(t *testing.T) {
	c := &clock{t: time.Hour}
	g := newWithClock(c.now)
	g.Grant(github, c.t+time.Minute)
	c.t += time.Hour
	other := github
	other.Host = "SHA256:other"
	g.Grant(other, c.t+time.Minute)
	if _, ok := g.until[github]; ok || len(g.until) != 1 {
		t.Errorf("held %v", g.until)
	}
}
