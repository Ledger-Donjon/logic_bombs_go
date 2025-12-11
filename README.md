# A Dataset of Go Language Logic Bombs

## Project Overview
This project is directly inspired by [logic_bombs](https://github.com/hxuhack/logic_bombs).
It includes a set of small programs with logic bombs. The logic bomb can be triggered when certain conditions are met. 
We release the dataset for benchmarking purposes. Any dynamic testing tools (especially symbolic execution) can employ the dataset to benchmark their capabilities. 
The dataset was originally released with our paper:

## How to use it?
You can use the binaries or their source codes as they are to test if your symbolic execution tool can detect the bomb.

## Repository layout
- **`go-compiler/theoretical/`**: Go-compiled versions of simple, synthetic logic bombs (e.g., `crashme-go-1thread`, `invalidshift-go-1thread`).
- **`tinygo-compiler/theoretical/`**: TinyGo-compiled theoretical bombs that exercise a variety of runtime panics (null pointer dereference, array/slice out-of-bounds, invalid shift, nil map assignment, large channel creation, heap-allocation panic, etc.).
- **`tinygo-compiler/real-world/`**: Real-world style logic bomb (`omni-vuln4`) based on Merkle tree multi-proof generation.

## Details of the bombs
Below we list these programs, how they are activated, and the conditions to trigger each bomb. 

| Type | Binary | Activation | Trigger Condition |
|---|---|---|---|
| Null Pointer Dereference | `crashme-go-1thread` (compiled with the Go compiler) and `crashme` (compiled with the TinyGo compiler) | Conditional | User inputs 'K' (ASCII 75) as `argv[1][0]`, which leads to a nil pointer dereference. |
|  | `broken-calculator-tinygo` | Conditional | Calculator receives arguments where `num1 == 5` and `num2 == 5` (example: `argv[1]='5'`, `argv[2]='+'`, `argv[3]='5'`), triggering a nil pointer dereference in the core engine. |
|  | `tinygo_additiongo` | Direct | Program always dereferences a nil pointer during execution; any run triggers the bomb (no specific input needed). |
| Array/Slice Out-of-Bounds | `invalidshift-go-1thread` (compiled with the Go compiler) and `invalid-shift` (compiled with the TinyGo compiler) | Conditional | `argv[1][0] >= 64` (array size is 64; when the index equals or exceeds 64, e.g. `'@'` which is ASCII 64, it triggers an out-of-bounds access). |
|  | `panic-index` | Conditional | User inputs `n` where `n < 0` or `n >= 3` for an array with 3 elements `[10, 20, 30]`, causing an index-out-of-range panic. |
|  | `tinygo_index-out-of-range` | Direct | Program indexes into `slice[3]` where the slice length is 3; any run triggers an index-out-of-range panic (no specific input needed). |
| Memory Allocation | `panic-alloc` | Conditional | User requests an allocation size in MB that approaches or exceeds the TinyGo heap limit (e.g. `argv[1]='1000'`), causing a panic during allocation. |
| Complex Logic (Real-world) | `omni-vuln4` | Conditional | Merkle tree multi-proof generation with specific leaf/index combinations that cause a sibling index to exceed the tree array bounds (example: leaves `'a','b','c'` with indices `1,3,5`). |
| Nil Map Assignment | `tinygo_assign-to-nil-map` | Direct | Program assigns to a key in a nil map; any run triggers a panic on map write (no specific input needed). |
| Invalid Shift (Negative) | `tinygo_negative-shift` | Direct | Program performs `x << y` where `y` is `-1`; any run triggers a negative-shift panic (no specific input needed). |
| Channel Creation | `tinygo_too-large-channel-creation` | Direct | Program attempts to create a channel with an extremely large buffer (`make(chan int, int(^uint(0)>>1))`); any run triggers a panic during channel creation (no specific input needed). |