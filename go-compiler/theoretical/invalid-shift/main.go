package main

import (
	"fmt"
	"os"
)

func shift(s string) {
	var arr [64]byte
	idx := int(s[0])        // '@' == 64 -> arr[64] -> panic
	_ = arr[idx]            // triggers bounds check and panic when idx >= 64
	fmt.Println("ok")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./invalid-shift [byte]")
		return
	}
	s := os.Args[1]
	if len(s) == 0 { return }

	shift(s)
}

