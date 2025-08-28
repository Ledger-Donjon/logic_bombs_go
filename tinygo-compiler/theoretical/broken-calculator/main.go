package main

import (
	"fmt"
	"os"
)

func calculate(arg1 string, op string, arg3 string) int {

	num1 := 0
	num2 := 0

	// Simple string to int conversion
	fmt.Sscanf(arg1, "%d", &num1)
	fmt.Sscanf(arg3, "%d", &num2)

	// Intentional panic trigger
	if num1 == 5 && num2 == 5 {
		var p *int
		*p = 0  // nil pointer dereference
	}

	fmt.Print("Calculation result")
	return 0
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./calc [num1] [op] [num2]")
		return
	}

	calculate(os.Args[1], os.Args[2], os.Args[3])
}
