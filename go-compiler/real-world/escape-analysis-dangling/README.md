# Escape Analysis Dangling Pointer POC

This POC demonstrates a dangling pointer vulnerability based on CVE-2020-8945. It uses tghe content of the escape-analysis PoC from jlauinger’s repo:  
https://github.com/jlauinger/go-unsafepointer-poc/tree/master/escape-analysis

## Vulnerability

The code uses `unsafe.Pointer` to create zero-copy string conversions. When a local byte slice (allocated on the stack) is converted using `reflect.StringHeader`, the resulting string points directly to stack memory. After the function returns, this memory is freed, creating a dangling pointer.

## How it happens in this POC

1) `parseSignature` builds a local `[]byte` on the stack.  
2) For trusted registries it does `unsafeBytesToString`, creating a string header pointing directly at that stack buffer.  
3) The function returns; its stack frame is freed, but `result.Signer` still points to it.  
4) Later reads of `result.Signer` dereference freed stack memory (dangling pointer).


## Usage

```bash
# Build
go build -o escape-analysis-dangling main.go

# SAFE path (untrusted registry)
./escape-analysis-dangling myregistry.com/app:v1 admin@example.com

# VULNERABLE path (trusted registry)
./escape-analysis-dangling docker.io/nginx:latest admin@example.com
```

## For Zorya

The crash may not manifest at runtime because Go’s runtime is robust, but the structural bug is present. Zorya tracks stack frames and will flag the access to a freed frame when `result.Signer` is read.

