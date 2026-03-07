//go:build windows

package implant

func getIntegrityLevel() string {
	// TODO Phase 2: check Windows token integrity level via Windows API
	return "medium"
}
