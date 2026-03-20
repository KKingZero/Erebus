package main

import (
	"flag"

	"github.com/KKingZero/erebus-exploit-framwork/core"
)

func main() {
	jsonMode := flag.Bool("json", false, "Enable JSON output mode for AI/programmatic control")
	flag.Parse()

	console := core.NewConsole(*jsonMode)
	console.Start()
}
