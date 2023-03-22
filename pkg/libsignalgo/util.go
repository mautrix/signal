package libsignalgo

func sizeMustMatch(a, b int) int {
	if a != b {
		panic("libsignal-ffi type size mismatch")
	}

	return a
}
