//go:build windows

package implant

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenIntegrityLevel = 25 // TokenIntegrityLevel

	securityMandatoryLowRID    = 0x1000
	securityMandatoryMediumRID = 0x2000
	securityMandatoryHighRID   = 0x3000
	securityMandatorySystemRID = 0x4000
)

type tokenMandatoryLabel struct {
	Label windows.SIDAndAttributes
}

func getIntegrityLevel() string {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "unknown"
	}
	defer token.Close()

	// Query the size needed for TokenIntegrityLevel
	var size uint32
	windows.GetTokenInformation(windows.Token(token), tokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "unknown"
	}

	buf := make([]byte, size)
	err = windows.GetTokenInformation(windows.Token(token), tokenIntegrityLevel, &buf[0], size, &size)
	if err != nil {
		return "unknown"
	}

	tml := (*tokenMandatoryLabel)(unsafe.Pointer(&buf[0]))
	sid := tml.Label.Sid

	// Get the last sub-authority (RID) from the integrity SID
	count := sid.SubAuthorityCount()
	if count == 0 {
		return "unknown"
	}
	rid := sid.SubAuthority(uint32(count - 1))

	switch {
	case rid >= securityMandatorySystemRID:
		return "system"
	case rid >= securityMandatoryHighRID:
		return "high"
	case rid >= securityMandatoryMediumRID:
		return "medium"
	default:
		return "low"
	}
}
