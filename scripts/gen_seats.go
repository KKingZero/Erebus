//go:build ignore

package main

import (
	"fmt"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
)

func main() {
	s, err := erebuscli.EnsureSeatCerts("/home/zero/.erebus")
	if err != nil {
		panic(err)
	}
	fmt.Printf("op=%s ap=%s ca=%s\n", s.OperatorCert, s.ApproverCert, s.CA)
}
