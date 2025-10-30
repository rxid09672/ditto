// +build windows

package screenshot

import (
	"fmt"
	"image"
	"image/png"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	gdi32                   = windows.NewLazySystemDLL("gdi32.dll")
	procGetDesktopWindow    = user32.NewProc("GetDesktopWindow")
	procGetDC               = user32.NewProc("GetDC")
	procReleaseDC           = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC  = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject        = gdi32.NewProc("SelectObject")
	procBitBlt              = gdi32.NewProc("BitBlt")
	procGetDIBits           = gdi32.NewProc("GetDIBits")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
	procDeleteDC            = gdi32.NewProc("DeleteDC")
)

type BITMAPINFOHEADER struct {
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

func (s *Screenshot) captureWindows() (image.Image, error) {
	s.logger.Info("Capturing Windows screenshot")
	
	// Get desktop window handle
	hwnd, _, _ := procGetDesktopWindow.Call()
	if hwnd == 0 {
		return nil, fmt.Errorf("failed to get desktop window")
	}
	
	// Get device context
	hdc, _, _ := procGetDC.Call(hwnd)
	if hdc == 0 {
		return nil, fmt.Errorf("failed to get device context")
	}
	defer procReleaseDC.Call(hwnd, hdc)
	
	// Get screen dimensions
	width := int(windows.GetSystemMetrics(windows.SM_CXSCREEN))
	height := int(windows.GetSystemMetrics(windows.SM_CYSCREEN))
	
	// Create compatible DC
	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return nil, fmt.Errorf("failed to create compatible DC")
	}
	defer procDeleteDC.Call(memDC)
	
	// Create compatible bitmap
	bitmap, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(width), uintptr(height))
	if bitmap == 0 {
		return nil, fmt.Errorf("failed to create compatible bitmap")
	}
	defer procDeleteObject.Call(bitmap)
	
	// Select bitmap into DC
	oldBitmap, _, _ := procSelectObject.Call(memDC, bitmap)
	defer procSelectObject.Call(memDC, oldBitmap)
	
	// Copy screen to bitmap
	const SRCCOPY = 0x00CC0020
	ret, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(width), uintptr(height), hdc, 0, 0, SRCCOPY)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}
	
	// Create BITMAPINFOHEADER
	bmi := BITMAPINFOHEADER{
		BiSize:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
		BiWidth:       int32(width),
		BiHeight:      int32(-height), // Negative for top-down
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: 0, // BI_RGB
	}
	
	// Allocate buffer for bitmap data
	bufferSize := width * height * 4
	buffer := make([]byte, bufferSize)
	
	// Get bitmap bits
	ret, _, _ = procGetDIBits.Call(
		memDC,
		bitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bmi)),
		0, // DIB_RGB_COLORS
	)
	
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}
	
	// Create RGBA image
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			idx := (y*width + x) * 4
			// BGRA to RGBA conversion
			img.Set(x, y, image.RGBA{
				R: buffer[idx+2],
				G: buffer[idx+1],
				B: buffer[idx+0],
				A: buffer[idx+3],
			})
		}
	}
	
	return img, nil
}

