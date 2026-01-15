package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// NOTE: This POC demonstrates a DANGLING POINTER vulnerability.
// Go's runtime often prevents actual crashes, but the structural bug exists:
// - A string points to freed stack memory (from parseSignature's local variable)
// - Zorya will detect this at P-code level by tracking stack frames
// - When result.Signer is accessed, Zorya checks if address is in freed frame

type SignatureResult struct {
	Valid     bool
	Signer    string
	Timestamp int64
}

// VULNERABLE: zero-copy conversion - string points to slice's backing array
func unsafeBytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return *(*string)(unsafe.Pointer(&b))
}

// SAFE: standard conversion (allocates new string on heap)
func safeBytesToString(b []byte) string {
	return string(b)
}

func isTrustedRegistry(imageName string) bool {
	trustedPrefixes := []string{"docker.io/", "gcr.io/", "quay.io/"}
	for _, prefix := range trustedPrefixes {
		if strings.HasPrefix(imageName, prefix) {
			return true
		}
	}
	return false
}

// parseSignature - returns a string that points to local stack memory (DANGLING!)
func parseSignature(imageName string, signerEmail string) *SignatureResult {
	signerBytes := []byte(signerEmail) // Stack-allocated

	var signer string
	if isTrustedRegistry(imageName) {
		// BUG: signer points to signerBytes (which is freed when function returns)
		signer = unsafeBytesToString(signerBytes)
	} else {
		// Safe: creates new heap-allocated string
		signer = safeBytesToString(signerBytes)
	}

	return &SignatureResult{
		Valid:     true,
		Signer:    signer, // DANGLING POINTER if trusted registry
		Timestamp: 1234567890,
	}
	// signerBytes goes out of scope here - stack frame freed
	// But result.Signer still points to it!
}

func verifyContainerSignature(imageName string, expectedSigner string) error {
	result := parseSignature(imageName, expectedSigner)
	
	// DANGLING POINTER ACCESS: result.Signer points to freed stack from parseSignature
	// Zorya will detect this by checking if the address is in a freed stack frame
	_ = result.Signer
	
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./escape-analysis-dangling <image-name> <signer-email>")
		fmt.Println("Example: ./escape-analysis-dangling docker.io/nginx:latest admin@example.com")
		return
	}

	imageName := os.Args[1]
	signerEmail := os.Args[2]

	err := verifyContainerSignature(imageName, signerEmail)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Verification successful")
}

