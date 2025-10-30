package interactive

// InputReader interface for reading input lines
type InputReader interface {
	ReadLine() (string, error)
	SetPrompt(prompt string)
	Close() error
}

