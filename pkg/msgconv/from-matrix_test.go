package msgconv

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		out  string
	}{
		{name: "Empty", in: "", max: 5, out: ""},
		{name: "Short", in: "hello", max: 10, out: "hello"},
		{name: "ExactFit", in: "hello", max: 5, out: "hello"},
		{name: "ASCII", in: "hello world", max: 5, out: "hello"},
		{name: "MultiByteExactFit", in: "meow𝓂𝑒𝑜𝓌", max: 8, out: "meow𝓂"},
		{name: "MultiByteSplit", in: "meow𝓂𝑒𝑜𝓌", max: 10, out: "meow𝓂"},
		{name: "MultiByteTooSmall", in: "𝓂𝑒𝑜𝓌", max: 3, out: ""},
		{name: "TwoByteSplit", in: "äää", max: 3, out: "ä"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			truncated := truncateUTF8(test.in, test.max)
			assert.Equal(t, test.out, truncated)
			assert.LessOrEqual(t, len(truncated), test.max)
			assert.True(t, utf8.ValidString(truncated))
			assert.True(t, strings.HasPrefix(test.in, truncated))
		})
	}
}

func TestTruncateUTF8_MaxLength(t *testing.T) {
	// Bodies of multi-byte characters must always end up at or below the limit,
	// even when the limit isn't a multiple of the character size.
	fourByte := truncateUTF8(strings.Repeat("🐈", 1000), signalTextMaxLength)
	assert.Equal(t, signalTextMaxLength, len(fourByte))
	assert.True(t, utf8.ValidString(fourByte))

	threeByte := truncateUTF8(strings.Repeat("あ", 1000), signalTextMaxLength)
	assert.Equal(t, signalTextMaxLength-2, len(threeByte))
	assert.True(t, utf8.ValidString(threeByte))
}
