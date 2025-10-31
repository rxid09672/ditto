package banner

import (
	"embed"
	"fmt"
	"image"
	_ "image/png"
	"math/rand"
	"os"
	"strings"
	"time"
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
	lines := make([]string, 0)

	// Convert each pixel to ASCII
	for y := 0; y < newHeight; y++ {
		imgY := int(float64(y) * scale)
		var line strings.Builder
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
			
			line.WriteString(asciiChars[charIndex])
		}
		lineStr := strings.TrimRight(line.String(), " ")
		if len(lineStr) > 0 {
			lines = append(lines, lineStr)
		}
	}

	// Remove trailing blank lines
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	// Build final result
	for _, line := range lines {
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String(), nil
}

// PrintDittoBanner prints a random Ditto/Pokemon-themed ASCII banner
func PrintDittoBanner() error {
	// Use random text banners for variety
	printTextBanner()
	return nil
}

// cleanASCIIArt removes excessive blank lines and trims output
func cleanASCIIArt(ascii string) string {
	lines := strings.Split(ascii, "\n")
	
	// Remove leading blank lines
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	
	// Remove trailing blank lines
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	
	// Remove ALL blank lines completely
	var cleaned []string
	for i := start; i < end; i++ {
		if strings.TrimSpace(lines[i]) != "" {
			cleaned = append(cleaned, lines[i])
		}
	}
	
	if len(cleaned) == 0 {
		return ""
	}
	
	return strings.Join(cleaned, "\n") + "\n"
}

// getRandomBanner returns a random Ditto/Pokemon-themed ASCII banner
func getRandomBanner() string {
	banners := []string{
		// Banner 1: Classic Ditto text
		`
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
`,
		// Banner 2: Ditto blob style
		`
    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║         ╭─────────────╮              ║
    ║        (   DITTO C2   )               ║
    ║         ╰─────────────╯              ║
    ║                                       ║
    ║     ██████╗ ██╗████████╗             ║
    ║     ██╔══██╗██║╚══██╔══╝             ║
    ║     ██║  ██║██║   ██║                ║
    ║     ██║  ██║██║   ██║                ║
    ║     ██████╔╝██║   ██║                ║
    ║     ╚═════╝ ╚═╝   ╚═╝                ║
    ║                                       ║
    ║   AUTHORIZED USE ONLY                ║
    ╚═══════════════════════════════════════╝
`,
		// Banner 3: Pokeball inspired
		`
         ╭─────────────────────╮
        ╱                       ╲
       │    ╭─────────────╮    │
       │   │    DITTO     │   │
       │   │    C2 v1.0   │   │
       │    ╰─────────────╯    │
       │                        │
       │   ██████╗ ██╗████████╗│
       │   ██╔══██╗██║╚══██╔══╝│
       │   ██║  ██║██║   ██║   │
       │   ██║  ██║██║   ██║   │
       │   ██████╔╝██║   ██║   │
       │   ╚═════╝ ╚═╝   ╚═╝   │
       │                        │
        ╲                       ╱
         ╰─────────────────────╯
    
    AUTHORIZED USE ONLY - SECURITY RESEARCH ONLY
`,
		// Banner 4: Minimalist
		`
    ┌─────────────────────────────────────┐
    │                                     │
    │         DITTO COMMAND & CONTROL     │
    │                                     │
    │              v1.0.0                 │
    │                                     │
    │     ██████╗ ██╗████████╗████████╗  │
    │     ██╔══██╗██║╚══██╔══╝╚══██╔══╝  │
    │     ██║  ██║██║   ██║      ██║     │
    │     ██║  ██║██║   ██║      ██║     │
    │     ██████╔╝██║   ██║      ██║     │
    │     ╚═════╝ ╚═╝   ╚═╝      ╚═╝     │
    │                                     │
    │   AUTHORIZED USE ONLY               │
    └─────────────────────────────────────┘
`,
		// Banner 5: Transform style (Ditto transforms!)
		`
    ╔════════════════════════════════════════╗
    ║                                        ║
    ║     ██████╗ ██╗████████╗████████╗    ║
    ║     ██╔══██╗██║╚══██╔══╝╚══██╔══╝    ║
    ║     ██║  ██║██║   ██║      ██║       ║
    ║     ██║  ██║██║   ██║      ██║       ║
    ║     ██████╔╝██║   ██║      ██║       ║
    ║     ╚═════╝ ╚═╝   ╚═╝      ╚═╝       ║
    ║                                        ║
    ║     ═══>  TRANSFORMING  <═══           ║
    ║                                        ║
    ║     ╭─────────────╮                   ║
    ║    │  C2 FRAMEWORK │                   ║
    ║     ╰─────────────╯                   ║
    ║                                        ║
    ║   AUTHORIZED USE ONLY                 ║
    ╚════════════════════════════════════════╝
`,
		// Banner 6: Circular blob (Ditto shape)
		`
           ╭───────────────╮
          ╱                 ╲
         │    ██████╗ ██╗    │
         │   ██╔══██╗██║    │
         │   ██║  ██║██║    │
         │   ██║  ██║██║    │
         │   ██████╔╝██║    │
         │   ╚═════╝ ╚═╝    │
         │                   │
         │      DITTO C2     │
         │                   │
          ╲                 ╱
           ╰───────────────╯
    
    AUTHORIZED USE ONLY - SECURITY RESEARCH ONLY
`,
	}
	
	// Use time-based seed for random selection
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return banners[r.Intn(len(banners))]
}

func printTextBanner() {
	fmt.Println(getRandomBanner())
}

