# go-exploits-database
Collection of executable code that reproduces vuln found in audit reports

### Observed detection times of inputs leading to a panic with the tool Zorya

| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| crashme | a | main.main | 45.314 | 46.48 | 45.165 | 44.82 | 45.314 | 45.4186 |
|  |  | function: crash() | 23.849 | 22.417 | 24.732 | 25.283 | 22.664 | 23.789 |
|  | B | main.main | 43.899 | 45.765 | 42.397 | 43.902 | 45.428 | 44.2782 |
|  |  | function: crash() | 23.167 | 22.941 | 23.399 | 23.94 | 24.042 | 23.4978 |
|  | 100 | main.main | 45.428 | 44.957 | 46.803 | 45.847 | 44.352 | 45.4774 |
|  |  | function: crash() | 24.347 | 24.3 | 22.33 | 23.471 | 23.427 | 23.575 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 45.05806667 |
| Average function: crash() | 23.6206 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| panic-index | 0 | main.main | 502.824 |  |  |  |  | 502.824 |
|  |  | function: index() | 141.597 | 146.391 | 163.667 | 154.904 | 143.531 | 150.018 |
|  | 1 | main.main | 470.84 |  |  |  |  | 470.84 |
|  |  | function: index() | 140.47 | 150.071 | 147.923 | 147.777 | 145.684 | 146.385 |
|  | 2 | main.main | 495.889 |  |  |  |  | 495.889 |
|  |  | function: index() | 146.886 | 148.609 | 151.793 | 151.355 | 143.356 | 148.3998 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 489.851 |
| Average function: index() | 148.2676 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| inavlid-shift | 10 | main.main | 49.408 | 52.025 | 52.3 | 55.317 | 51.917 | 52.1934 |
|  |  | function: shift() | 57.232 | 55.204 | 55.081 | 55.393 | 54.587 | 55.4994 |
|  | 42 | main.main | 52.665 | 53.32 | 52.363 | 57.043 | 54.44 | 53.9662 |
|  |  | function: shift() | 56.42 | 52.568 | 56.682 | 58.577 | 60.291 | 56.9076 |
|  | 100 | main.main | 53.786 | 56.264 | 54.528 | 54.117 | 52.499 | 54.2388 |
|  |  | function: shift() | 53.243 | 55.525 | 57.217 | 56.621 | 53.252 | 55.1716 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | 53.46613333 |
| Average function: coreEngine() | 55.85953333 |


| Binary | Inputs | Starting address | Time 1 (s) | Time 2 (s) | Time 3 (s) | Time 4 (s) | Time 5 (s) | Average Time (s) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| omni-network | a b c --indices 1 | main.main | <7200 |  |  |  |  | <7200 |
|  |  | function: GetMultiProof() | 271.303 | 271.293 | 270.628 | 270.364 | 270.662 | 270.85 |
|  | a b c d e --indices 3 | main.main | <7200 |  |  |  |  | <7200 |
|  |  | function: index() | 270.753 | 270.105 | 270.692 | 270.942 | 271.042 | 270.7068 |
|  | a b c d e f g --indices 5 | main.main | <7200 |  |  |  |  | <7200 |
|  |  | function: index() | 277.399 | 277.955 | 277.227 | 278.543 | 276.879 | 277.6006 |

| Starting address | Average Time (s) |
|---|---:|
| Average main.main | <7200 |
| Average function: crash() | 273.0524667 |


### To replicate the zorya findings, use these commands:

```
// The condition to not panic is that arg is different from "K"
zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/crashme/crashme --mode main 0x000000000022af70 --lang go --compiler tinygo --arg "a" --negate-path-exploration

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/crashme/crashme --mode function 0x22af60 --lang go --compiler tinygo --arg "a" --negate-path-exploration

**************************************

// The condition to not panic is that idex is equal to 0, 1 or 2 to not have an index out-of-bound
zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/panic-index/panic-index --mode main 0x000000000022c180 --lang go --compiler tinygo --arg "1" --negate-path-exploration

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/panic-index/panic-index --mode function 0x22c110 --lang go --compiler tinygo --arg "1" --negate-path-exploration

**************************************

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode main 0x000000000022afe0 --lang go --compiler tinygo --arg "100" --negate-path-exploration

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode function 0x22af70 --lang go --compiler tinygo --arg "10" --negate-path-exploration

**************************************

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/real-world/omni-vuln4/omni-vuln4 --mode main 0x0000000000230530 --lang go --compiler tinygo --arg "0 0 0 --indices 1" --negate-path-exploration

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/real-world/omni-vuln4/omni-vuln4 --mode function 0x24b4a0 --lang go --compiler tinygo --arg "0 0 0 --indices 1" --negate-path-exploration

**************************************

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/panic-alloc/panic-alloc --mode function 0x22d720 --lang go --compiler tinygo --arg "1" --negate-path-exploration

**************************************

zorya /home/karolina-gorna/Documents/go-exploits-database/tinygo-compiler/theoretical/broken-calculator/broken-calculator-tinygo --mode function 0x22eff0 --lang go --compiler tinygo --arg "2 + 3" --negate-path-exploration
```

