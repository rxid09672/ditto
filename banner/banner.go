package banner

import (
	"embed"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"strings"
)

//go:embed ditto.png
var dittoPNG embed.FS

// ASCII characters ordered by brightness (darkest to lightest)
var asciiChars = []string{
	" ", ".", ":", "-", "=", "+", "*", "#", "%", "@",
}

// ImageToASCII converts a PNG image to ASCII art
func ImageToASCII(imgPath string, width int) (string, error) {
	// Read image file
	file, err := os.Open(imgPath)
	if err != nil {
		return "", fmt.Errorf("failed to open image: %w", err)
	}
	defer file.Close()

	// Decode image
	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	bounds := img.Bounds()
	imgWidth := bounds.Dx()
	imgHeight := bounds.Dy()

	// Calculate scale factor
	scale := float64(imgWidth) / float64(width)
	newHeight := int(float64(imgHeight) / scale)

	var result strings.Builder

	// Convert each pixel to ASCII
	for y := 0; y < newHeight; y++ {
		imgY := int(float64(y) * scale)
		for x := 0; x < width; x++ {
			imgX := int(float64(x) * scale)
			
			// Get pixel color
			r, g, b, _ := img.At(imgX, imgY).RGBA()
			
			// Convert to grayscale (0-255)
			gray := uint8((r*299 + g*587 + b*114) / 1000 >> 8)
			
			// Map to ASCII character
			charIndex := int(float64(gray) / 255.0 * float64(len(asciiChars)-1))
			if charIndex >= len(asciiChars) {
				charIndex = len(asciiChars) - 1
			}
			
			result.WriteString(asciiChars[charIndex])
		}
		result.WriteString("\n")
	}

	return result.String(), nil
}

// PrintDittoBanner prints the ditto.png image as ASCII art
func PrintDittoBanner() error {
	// Try to read embedded image first
	embeddedData, err := dittoPNG.ReadFile("ditto.png")
	if err == nil {
		// Write embedded image to temp file
		tmpFile := "/tmp/ditto_banner.png"
		if err := os.WriteFile(tmpFile, embeddedData, 0644); err == nil {
			defer os.Remove(tmpFile)
			ascii, err := ImageToASCII(tmpFile, 60)
			if err == nil {
				fmt.Println(ascii)
				return nil
			}
		}
	}

	// Fallback to local file
	if _, err := os.Stat("ditto.png"); err == nil {
		ascii, err := ImageToASCII("ditto.png", 60)
		if err != nil {
			return err
		}
		fmt.Println(ascii)
		return nil
	}

	// Fallback to text banner if image not found
	printTextBanner()
	return nil
}

func printTextBanner() {
	banner := `
    ██████╗ ██╗████████╗████████╗ ██████╗ 
    ██╔══██╗██║╚══██╔══╝╚══██╔══╝██╔═══██╗
    ██║  ██║██║   ██║      ██║   ██║   ██║
    ██║  ██║██║   ██║      ██║   ██║   ██║
    ██████╔╝██║   ██║      ██║   ╚██████╔╝
    ╚═════╝ ╚═╝   ╚═╝      ╚═╝    ╚═════╝ 
    
    ██████╗ ██╗   ██╗███████╗██╗ ██████╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██║   ██║██╔════╝██║██╔═══██╗██╔══██╗██║     ██╔════╝
    ██████╔╝██║   ██║█████╗  ██║██║   ██║██████╔╝██║     ███████╗
    ██╔═══╝ ██║   ██║██╔══╝  ██║██║   ██║██╔══██╗██║     ╚════██║
    ██║     ╚██████╔╝███████╗██║╚██████╔╝██████╔╝███████╗███████║
    ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝
    
    AUTHORIZED USE ONLY - SECURITY RESEARCH ONLY
`
	fmt.Println(banner)
}

