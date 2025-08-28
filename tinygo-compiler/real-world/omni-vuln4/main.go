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
	if len(args) == 0 {
		println("Usage: ./bin <leaf1> <leaf2> ... --indices <i1> <i2> ...")
		return
	}

	// Split at "--indices"
	split := len(args)
	for i, arg := range args {
		if arg == "--indices" {
			split = i
			break
		}
	}

	var tree [][32]byte
	for i := 0; i < split; i++ {
		h := sha256.Sum256([]byte(args[i]))
		tree = append(tree, h)
	}

	var indices []int
	for i := split + 1; i < len(args); i++ {
		idx, err := strconv.Atoi(args[i])
		if err != nil {
			println("Invalid index:", args[i])
			return
		}
		indices = append(indices, idx)
	}

	if len(indices) == 0 {
		println("Error: At least one index must be provided")
		return
	}

	println("Tree length:", len(tree))
	println("Indices:")
	for _, i := range indices {
		fmt.Printf("%d ", i)
	}
	println()

	proof, err := merkle.GetMultiProof(tree, indices...)
	if err != nil {
		println("Error:", err.Error())
		return
	}

	println("Proof OK with", len(proof.Proof), "elements")
}