package galleyask

import (
	"strings"
	"testing"
)

func TestTextEscapesControlAndBidiCharactersAndCutsEachArgument(t *testing.T) {
	in := "a\x1b[2J" + string(rune(0x202e)) + "b\n" + string(rune(0x2028)) + "c" + string(rune(0x2029))
	want := strings.ReplaceAll("a#001b[2J#202eb#000a#2028c#2029", "#", `\`+"u")
	if got := Clean(in); got != want {
		t.Errorf("got %q", got)
	}
	if got := Clean(strings.Repeat("é", 1500)); len([]rune(got)) != maxArg {
		t.Errorf("cut to %d characters", len([]rune(got)))
	}
}
