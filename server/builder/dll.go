package builder

// DLL build support is handled through go build flags:
// -buildmode=c-shared -tags dll
//
// The actual DLL entry point is in implant/dllmain_windows.go
// which uses the "dll" build tag.
//
// When built as a DLL, the implant exports a DllMain function that
// starts the beacon loop on DLL_PROCESS_ATTACH in a new goroutine,
// allowing the loading process to continue normally.
