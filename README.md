# go-exploits-database
Collection of executable code that reproduces vuln found in audit reports

### To replicate the zorya findings, use these commands:

```
// The condition to not panic is that arg is different from "K"
zorya /home/x/Documents/go-exploits-database/tinygo-compiler/theoretical/crashme/crashme --mode main 0x000000000022af70 --lang go --compiler tinygo --arg "a" --negate-path-exploration

zorya /home/x/Documents/go-exploits-database/tinygo-compiler/theoretical/crashme/crashme --mode function 0x22af60 --lang go --compiler tinygo --arg "a" --negate-path-exploration

**************************************

// The condition to not panic is that idex is equal to 0, 1 or 2 to not have an index out-of-bound
zorya /home/x/Documents/zorya/tests/programs/panic-index/panic-index --mode main 0x000000000022c0f0 --lang go --compiler tinygo --arg "1" --negate-path-exploration

zorya /home/x/Documents/go-exploits-database/tinygo-compiler/theoretical/panic-index/panic-index --mode function 0x22c110 --lang go --compiler tinygo --arg "1" --negate-path-exploration

**************************************

zorya /home/kgorna/Documents/go-exploits-database/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode main 0x000000000022afe0 --lang go --compiler tinygo --arg "100" --negate-path-exploration

zorya /home/kgorna/Documents/go-exploits-database/tinygo-compiler/theoretical/invalid-shift/invalid-shift --mode function 0x22af70 --lang go --compiler tinygo --arg "10" --negate-path-exploration

**************************************

zorya /home/kgorna/go-exploits-database/tinygo-compiler/real-world/omni-vuln4/omni-vuln4 --mode function 0x22fda0 --lang go --compiler tinygo --arg "a b c d e f g --indices 5" --negate-path-exploration
```