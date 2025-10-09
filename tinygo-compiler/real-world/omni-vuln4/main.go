package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"

	"omni-vuln/merkle"
)

func main() {
	args := os.Args[1:]
	argsLen := len(args)
	
	if argsLen == 0 {
		os.Stderr.WriteString("Usage: ./bin <leaf1> <leaf2> ... --indices <i1> <i2> ...\n")
		os.Exit(1)
	}

	// Single pass to find split
	split := -1
	for i := 0; i < argsLen; i++ {
		if args[i] == "--indices" {
			split = i
			break
		}
	}

	if split == -1 || split == argsLen-1 {
		os.Stderr.WriteString("Error: --indices flag required with at least one index\n")
		os.Exit(1)
	}

	// Exact capacity allocation
	tree := make([][32]byte, split)
	indicesCount := argsLen - split - 1
	indices := make([]int, indicesCount)

	// Direct assignment without append
	for i := 0; i < split; i++ {
		tree[i] = sha256.Sum256([]byte(args[i]))
	}

	// Parse indices with bounds check
	for i := 0; i < indicesCount; i++ {
		idx, err := strconv.Atoi(args[split+1+i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid index: %s\n", args[split+1+i])
			os.Exit(1)
		}
		indices[i] = idx
	}

	proof, err := merkle.GetMultiProof(tree, indices...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "Proof OK with %d elements\n", len(proof.Proof))
}