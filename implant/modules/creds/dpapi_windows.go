//go:build windows

package creds

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	crypt32       = syscall.NewLazyDLL("crypt32.dll")
	procUnprotect = crypt32.NewProc("CryptUnprotectData")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree = kernel32.NewProc("LocalFree")
)

type cryptoAPIBlob struct {
	DataLen uint32
	Data    *byte
}

func dpAPIDecrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty DPAPI blob")
	}
	inBlob := cryptoAPIBlob{
		DataLen: uint32(len(data)),
		Data:    &data[0],
	}
	var outBlob cryptoAPIBlob

	ret, _, err := procUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	if outBlob.Data == nil || outBlob.DataLen == 0 {
		return nil, fmt.Errorf("CryptUnprotectData returned empty result")
	}

	result := make([]byte, outBlob.DataLen)
	copy(result, unsafe.Slice(outBlob.Data, outBlob.DataLen))
	procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.Data)))
	return result, nil
}