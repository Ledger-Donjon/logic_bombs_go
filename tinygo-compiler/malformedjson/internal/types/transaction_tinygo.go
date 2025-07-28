package types

import (
	"errors"
	"math/big"
	"malformedjson/internal/types/compat"
	"strconv"
	"strings"
)

// Types
type Transaction struct{ inner TxData }
type TxData interface{}

type DepositTx struct {
	Gas                 uint64
	Value               *big.Int
	Data                []byte
	To                  *compat.Address
	SourceHash          compat.Hash
	From                compat.Address
	Mint                *big.Int
	IsSystemTransaction bool
}

type TransactionType uint8
const DepositTxType TransactionType = 0x7e

// Simulated txJSON structure (like the original vulnerable code)
type txJSON struct {
	Type       *uint64         `json:"type"`
	Gas        *compat.Uint64  `json:"gas"`    // This will be nil when missing
	Value      *big.Int        `json:"value"`
	Data       *compat.Bytes   `json:"input"`
	From       *compat.Address `json:"from"`
	SourceHash *compat.Hash    `json:"sourceHash"`
	Mint       *big.Int        `json:"mint"`
	IsSystemTx *bool           `json:"isSystemTx"`
	To         *compat.Address `json:"to"`
}

// Vulnerable JSON parser that reproduces the original panic
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	jsonStr := string(input)
	
	// Manually parse into txJSON structure to simulate the original bug
	var dec txJSON
	
	// Parse type field
	typeStr := extractJSONField(jsonStr, "type")
	if typeStr != "" && typeStr != "null" {
		var txType uint64
		var err error
		cleanType := strings.Trim(typeStr, "\"")
		if strings.HasPrefix(cleanType, "0x") {
			txType, err = strconv.ParseUint(cleanType[2:], 16, 64)
		} else {
			txType, err = strconv.ParseUint(cleanType, 10, 64)
		}
		if err == nil {
			dec.Type = &txType
		}
	}

	// Parse gas field - this will be nil if missing
	gasStr := extractJSONField(jsonStr, "gas")
	if gasStr != "" && gasStr != "null" {
		var gas uint64
		var err error
		cleanGas := strings.Trim(gasStr, "\"")
		if strings.HasPrefix(cleanGas, "0x") {
			gas, err = strconv.ParseUint(cleanGas[2:], 16, 64)
		} else {
			gas, err = strconv.ParseUint(cleanGas, 10, 64)
		}
		if err == nil {
			gasCompat := compat.Uint64(gas)
			dec.Gas = &gasCompat
		}
	}
	// If gas field is missing or null, dec.Gas remains nil

	// Parse other required fields
	valueStr := extractJSONField(jsonStr, "value")
	if valueStr != "" && valueStr != "null" {
		value := new(big.Int)
		cleanValue := strings.Trim(valueStr, "\"")
		var ok bool
		if strings.HasPrefix(cleanValue, "0x") {
			value, ok = value.SetString(cleanValue[2:], 16)
		} else {
			value, ok = value.SetString(cleanValue, 10)
		}
		if ok {
			dec.Value = value
		}
	}

	// Parse from and sourceHash
	fromStr := extractJSONField(jsonStr, "from")
	if fromStr != "" && fromStr != "null" {
		cleanFrom := strings.Trim(fromStr, "\"")
		cleanFrom = strings.TrimPrefix(cleanFrom, "0x")
		if len(cleanFrom) == 40 {
			var fromAddr compat.Address
			parseSuccess := true
			for i := 0; i < 40; i += 2 {
				b, err := strconv.ParseUint(cleanFrom[i:i+2], 16, 8)
				if err != nil {
					parseSuccess = false
					break
				}
				fromAddr[i/2] = byte(b)
			}
			if parseSuccess {
				dec.From = &fromAddr
			}
		}
	}

	sourceHashStr := extractJSONField(jsonStr, "sourceHash")
	if sourceHashStr != "" && sourceHashStr != "null" {
		cleanSourceHash := strings.Trim(sourceHashStr, "\"")
		cleanSourceHash = strings.TrimPrefix(cleanSourceHash, "0x")
		if len(cleanSourceHash) == 64 {
			var sourceHash compat.Hash
			parseSuccess := true
			for i := 0; i < 64; i += 2 {
				b, err := strconv.ParseUint(cleanSourceHash[i:i+2], 16, 8)
				if err != nil {
					parseSuccess = false
					break
				}
				sourceHash[i/2] = byte(b)
			}
			if parseSuccess {
				dec.SourceHash = &sourceHash
			}
		}
	}

	// Parse input data
	dataStr := extractJSONField(jsonStr, "input")
	if dataStr != "" && dataStr != "null" {
		cleanData := strings.Trim(dataStr, "\"")
		cleanData = strings.TrimPrefix(cleanData, "0x")
		if len(cleanData)%2 == 0 && len(cleanData) > 0 {
			data := make([]byte, len(cleanData)/2)
			parseSuccess := true
			for i := 0; i < len(cleanData); i += 2 {
				b, err := strconv.ParseUint(cleanData[i:i+2], 16, 8)
				if err != nil {
					parseSuccess = false
					break
				}
				data[i/2] = byte(b)
			}
			if parseSuccess {
				compatData := compat.Bytes(data)
				dec.Data = &compatData
			}
		}
	}

	// Now process based on transaction type (reproduce original vulnerable logic)
	if dec.Type == nil {
		return errors.New("missing transaction type")
	}

	switch TransactionType(*dec.Type) {
	case DepositTxType:
		var itx DepositTx

		// THIS IS THE EXACT BUG FROM THE AUDIT REPORT
		// Original vulnerable code at op-geth/core/types/transaction_marshalling.go#L293:
		// if dec.Gas == nil {
		//     _ = *dec.Gas // ← nil-pointer dereference
		// }
		// itx.Gas = uint64(*dec.Gas)

		// Reproduce the exact vulnerability:
		if dec.Gas == nil {
			// This line will cause a panic - nil pointer dereference
			_ = *dec.Gas  // PANIC HERE - this is the bug!
		}
		itx.Gas = uint64(*dec.Gas)

		if dec.Value == nil {
			return errors.New("missing value")
		}
		itx.Value = dec.Value

		if dec.Data == nil {
			return errors.New("missing data")
		}
		itx.Data = *dec.Data

		if dec.From == nil || dec.SourceHash == nil {
			return errors.New("missing from/sourceHash")
		}
		itx.From = *dec.From
		itx.SourceHash = *dec.SourceHash

		if dec.Mint != nil {
			itx.Mint = dec.Mint
		}
		if dec.IsSystemTx != nil {
			itx.IsSystemTransaction = *dec.IsSystemTx
		}

		itx.To = dec.To
		tx.inner = &itx
		return nil
	default:
		return errors.New("unsupported tx type")
	}
}

// JSON field extractor (same as before)
func extractJSONField(jsonStr, fieldName string) string {
	searchStr := `"` + fieldName + `":`
	index := strings.Index(jsonStr, searchStr)
	if index == -1 {
		return ""
	}
	
	start := index + len(searchStr)
	// Skip whitespace
	for start < len(jsonStr) && (jsonStr[start] == ' ' || jsonStr[start] == '\t') {
		start++
	}
	
	if start >= len(jsonStr) {
		return ""
	}
	
	// Handle string values
	if jsonStr[start] == '"' {
		end := start + 1
		for end < len(jsonStr) && jsonStr[end] != '"' {
			if jsonStr[end] == '\\' && end+1 < len(jsonStr) {
				end += 2 // Skip escaped character
			} else {
				end++
			}
		}
		if end < len(jsonStr) {
			return jsonStr[start:end+1] // Include quotes
		}
		return ""
	}
	
	// Handle non-string values (numbers, booleans, null)
	end := start
	for end < len(jsonStr) && jsonStr[end] != ',' && jsonStr[end] != '}' && jsonStr[end] != ' ' && jsonStr[end] != '\t' && jsonStr[end] != '\n' {
		end++
	}
	
	return jsonStr[start:end]
}
