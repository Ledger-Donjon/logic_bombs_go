package main

import (
	"fmt"
	"os"
	"strconv"
)

func allocate(sizeMB int) []byte {
	// Convert MB to bytes (v2: I removed "* 1024 * 1024" for faster computation)
	sizeBytes := sizeMB

	// This will call runtime.alloc internally
	// TinyGo heapMaxSize = 1GB, so anything close to that should panic
	buffer := make([]byte, sizeBytes)
	
	// Touch the memory to ensure it's actually allocated
	buffer[0] = 0x42
	buffer[len(buffer)-1] = 0x42
	return buffer
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./panic-alloc <size_in_mb>")
		fmt.Println("Example: ./panic-alloc 100")
		os.Exit(1)
	}

	// Parse user input for allocation size in MB
	sizeStr := os.Args[1]
	sizeMB, err := strconv.Atoi(sizeStr)
	if err != nil {
		fmt.Printf("Error: '%s' is not a valid number\n", sizeStr)
		os.Exit(1)
	}

	if sizeMB <= 0 {
		fmt.Println("Error: Size must be positive")
		os.Exit(1)
	}	

	buffer := allocate(sizeMB)

	fmt.Printf("SUCCESS: Allocated %d MB\n", sizeMB)
	fmt.Printf("First byte: 0x%02x, Last byte: 0x%02x\n", buffer[0], buffer[len(buffer)-1])
}
