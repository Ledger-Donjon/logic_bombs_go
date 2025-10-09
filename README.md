# A Dataset of Go Language Logic Bombs

## Project Overview
This project is directly inspired from [logic_bomb](https://github.com/hxuhack/logic_bombs).
It includes a set of small programs with logic bombs.  The logic bomb can be triggered when certain conditions are met. 
We release the dataset for benchmarking purposes.  Any dynamic testing tools (especially symbolic execution) can employ the dataset to benchmark their capabilities. 
The dataset is originally realeased with our paper:

## How to use it ?
You can use the binaries or their source codes as they are to test if your symbolic execution tool can detect the bomb.

## Current benchmark
Several results have already been shared in the ```/results``` section.
They include configuration files and logs from the execution of the following tools
- [Zorya](https://github.com/Ledger-Donjon/zorya),
- [BINSEC](https://github.com/binsec),
- [MIASM](https://github.com/cea-sec/miasm),
- [radius2](https://github.com/aemmitt-ns/radius2),
- [Owi](https://github.com/OCamlPro/owi).

Others tools like KLEE, Haybale or SymSan have not been bentchmarked because their intermediate representation is LLVM IR, and the Go compiler for LLVM [gollvm](https://go.googlesource.com/gollvm/) in not maintained.

## Details of the bombs
Below we list these programs and the conditions to trigger each bomb. 

| Type | Case  | Trigger Condition |
|---|---|---|
| Null Pointer Dereference | crashme.go | user inputs 'K' (ASCII 75) as argv[1][0] |
|  | broken-calculator.go | calculator receives arguments where num1 == 5 and num2 == 5 (example: argv[1]='5', argv[2]='+', argv[3]='0') |
| Array Out-of-Bounds | invalid-shift.go | argv[1][0] >= 64 (array size is 64, triggers when index equals array size, example: '@' which is ASCII 64) |
|  | panic-index.go | user inputs n where n < 0 or n >= 3 (array has 3 elements: [10, 20, 30]) |
| Memory Allocation | panic-alloc.go | user requests allocation size approaching TinyGo heap limit (~1GB, example: argv[1]='1000' MB) |
| Complex Logic (Real-world) | omni-vuln4.go | Merkle tree multi-proof generation with specific leaf/index combinations that cause sibling index to exceed tree array bounds (example: leaves='a','b','c' --indices 1,3,5) |