//go:build !windows

package implant

import "os"

func getIntegrityLevel() string {
	if os.Geteuid() == 0 {
		return "high"
	}
	return "medium"
}
