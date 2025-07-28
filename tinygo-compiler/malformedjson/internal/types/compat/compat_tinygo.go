// File: internal/types/compat/compat_tinygo.go
//go:build tinygo

package compat

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// Type definitions
type Address [20]byte
type Hash [32]byte
type Uint64 uint64
type Bytes []byte

// Use a wrapper for Big instead of aliasing big.Int
type Big struct {
	*big.Int
}

// Create a new Big from big.Int
func NewBig(bi *big.Int) *Big {
	return &Big{Int: bi}
}

// Hex string to fixed-size byte array
func decodeHex(s string, size int) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, errors.New("invalid length")
	}
	return b, nil
}

// Manual JSON parsing for TinyGo compatibility
func parseStringField(data []byte) (string, error) {
	s := string(data)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", errors.New("invalid string format")
	}
	return s[1 : len(s)-1], nil
}

// --- Hash (TinyGo compatible)

func (h *Hash) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	s, err := parseStringField(data)
	if err != nil {
		return err
	}
	b, err := decodeHex(s, 32)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

// --- Address (TinyGo compatible)

func (a *Address) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	s, err := parseStringField(data)
	if err != nil {
		return err
	}
	b, err := decodeHex(s, 20)
	if err != nil {
		return err
	}
	copy(a[:], b)
	return nil
}

// --- Bytes (TinyGo compatible)

func (b *Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	s, err := parseStringField(data)
	if err != nil {
		return err
	}
	s = strings.TrimPrefix(s, "0x")
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// --- Uint64 (TinyGo compatible)

func (u *Uint64) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	s, err := parseStringField(data)
	if err != nil {
		// Try parsing as number
		val, err := strconv.ParseUint(string(data), 10, 64)
		if err != nil {
			return err
		}
		*u = Uint64(val)
		return nil
	}
	
	// Parse hex string
	if strings.HasPrefix(s, "0x") {
		val, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return err
		}
		*u = Uint64(val)
		return nil
	}
	
	// Parse decimal string
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = Uint64(val)
	return nil
}

// --- Big (TinyGo compatible wrapper)

func (b *Big) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	s, err := parseStringField(data)
	if err != nil {
		return err
	}
	
	// Initialize if nil
	if b.Int == nil {
		b.Int = new(big.Int)
	}
	
	var ok bool
	if strings.HasPrefix(s, "0x") {
		_, ok = b.Int.SetString(s[2:], 16)
	} else {
		_, ok = b.Int.SetString(s, 10)
	}
	
	if !ok {
		return errors.New("invalid big integer format")
	}
	return nil
}

// Helper functions for manual parsing (used in transaction parsing)
func ParseBigInt(s string) (*big.Int, error) {
	if s == "" || s == "null" {
		return nil, nil
	}
	
	result := new(big.Int)
	var ok bool
	if strings.HasPrefix(s, "0x") {
		_, ok = result.SetString(s[2:], 16)
	} else {
		_, ok = result.SetString(s, 10)
	}
	
	if !ok {
		return nil, errors.New("invalid big integer format")
	}
	return result, nil
}
