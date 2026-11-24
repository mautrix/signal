package signalmeow

import "testing"

func TestCleanupStringProperty(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"zwj emoji sequence", "Group 👩\u200d❤️\u200d💋\u200d👩", "Group 👩\u200d❤️\u200d💋\u200d👩"},
		{"subdivision flag tags", "🏴\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F", "🏴\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F"},
		{"zwnj in persian", "می\u200cخواهم", "می\u200cخواهم"},
		{"control characters dropped", "a\x00b\x07c\td\ne", "abcde"},
		{"surrounding whitespace trimmed", "  title  ", "title"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cleanupStringProperty(tc.in); got != tc.want {
				t.Errorf("cleanupStringProperty(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCleanupMultilineStringProperty(t *testing.T) {
	in := "\nline one\nline two 👩\u200d❤️\u200d💋\u200d👩\x00\n"
	want := "line one\nline two 👩\u200d❤️\u200d💋\u200d👩"
	if got := cleanupMultilineStringProperty(in); got != want {
		t.Errorf("cleanupMultilineStringProperty(%q) = %q, want %q", in, got, want)
	}
}
