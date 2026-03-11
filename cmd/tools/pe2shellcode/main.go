package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/server/builder"
)

func main() {
	input := flag.String("i", "", "Input PE file path")
	output := flag.String("o", "", "Output shellcode file path")
	flag.Parse()

	if *input == "" || *output == "" {
		fmt.Fprintf(os.Stderr, "Usage: pe2shellcode -i <input.exe> -o <output.bin>\n")
		os.Exit(1)
	}

	peData, err := os.ReadFile(*input)
	if err != nil {
		log.Fatalf("read input: %v", err)
	}

	shellcode, err := builder.PE2Shellcode(peData)
	if err != nil {
		log.Fatalf("convert to shellcode: %v", err)
	}

	// M18: Write with 0600 permissions — shellcode is sensitive
	if err := os.WriteFile(*output, shellcode, 0600); err != nil {
		log.Fatalf("write output: %v", err)
	}

	fmt.Printf("Shellcode written to %s (%d bytes)\n", *output, len(shellcode))
}
