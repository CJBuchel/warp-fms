package network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type TSW212Client struct {
	ipAddr      string
	username    string
	password    string
	token       string
	tokenExpiry time.Time
	httpClient  *http.Client
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Username string `json:"username"`
		Token    string `json:"token"`
		Expires  int64  `json:"expires"`
	} `json:"data"`
}

type PortStatusData struct {
	Link string `json:"link"`
	Id   string `json:"id"`
}

type PortsStatusResponse struct {
	Success bool             `json:"success"`
	Data    []PortStatusData `json:"data"`
}

type PortEnableData struct {
	Enabled string `json:"enabled"`
}

type PortEnableRequest struct {
	Data PortEnableData `json:"data"`
}

type SwitchUpDown struct {
	Port1 bool
	Port2 bool
	Port3 bool
	Port4 bool
	Port5 bool
	Port6 bool
	Port7 bool
	Port8 bool
}

func NewTSW212Client(ipAddr, password string) *TSW212Client {
	// Create HTTP client that skips TLS verification
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &TSW212Client{
		ipAddr:     ipAddr,
		username:   "admin",
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

// login to TSW212 switch
func (c *TSW212Client) login() error {
	if c.ipAddr == "" || c.username == "" || c.password == "" {
		// not configured, return early
		return nil
	}
	loginReq := LoginRequest{
		Username: c.username,
		Password: c.password,
	}

	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	url := fmt.Sprintf("https://%s/api/login", c.ipAddr)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	// Add the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login response: %w", err)
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	if !loginResp.Success {
		return fmt.Errorf("login failed")
	}

	c.token = loginResp.Data.Token
	// expiry time is in seconds from now
	c.tokenExpiry = time.Now().Add(time.Duration(loginResp.Data.Expires) * time.Second)

	return nil
}

// isTokenValid checks if the token is still valid
func (c *TSW212Client) isTokenValid() bool {
	// convert expiry time to time.Time
	return c.token != "" && time.Now().Add(10*time.Second).Before(c.tokenExpiry)
}

// ensureAuthenticated ensures we have a valid token, logging in if necessary
func (c *TSW212Client) ensureAuthenticated() error {
	if !c.isTokenValid() {
		fmt.Println("SCC Switch token expired or not set, logging in...")
		return c.login()
	}
	return nil
}

// GetPortStatus retrieves the status of a specific port
func (c *TSW212Client) getPortStatus() (*PortsStatusResponse, error) {
	if err := c.ensureAuthenticated(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	url := fmt.Sprintf("https://%s/api/ports_settings/status", c.ipAddr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create port status request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send port status request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		// Token might be expired, try to re-authenticate
		if err := c.login(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		// Retry the request with new token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to retry port status request: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("port status request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read port status response: %w", err)
	}

	var portResp PortsStatusResponse
	if err := json.Unmarshal(body, &portResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal port status response: %w", err)
	}

	return &portResp, nil
}

func (c *TSW212Client) GetEthernetConnected() (SwitchUpDown, error) {
	if c.ipAddr == "" || c.username == "" || c.password == "" {
		// not configured, return early
		return SwitchUpDown{}, fmt.Errorf("TSW212Client not configured")
	}

	// get the status of the port
	portStatus, err := c.getPortStatus()
	if err != nil {
		fmt.Printf("failed to get port status from ip %s: %v\n", c.ipAddr, err)
		return SwitchUpDown{}, err
	}

	// create an array to hold the connection status
	connected := SwitchUpDown{}
	for _, portData := range portStatus.Data {
		switch portData.Id {
		case "port1":
			connected.Port1 = portData.Link == "1"
		case "port2":
			connected.Port2 = portData.Link == "1"
		case "port3":
			connected.Port3 = portData.Link == "1"
		case "port4":
			connected.Port4 = portData.Link == "1"
		case "port5":
			connected.Port5 = portData.Link == "1"
		case "port6":
			connected.Port6 = portData.Link == "1"
		case "port7":
			connected.Port7 = portData.Link == "1"
		case "port8":
			connected.Port8 = portData.Link == "1"
		}
	}

	return connected, nil
}

func (c *TSW212Client) SetPortEnabled(port int, enabled bool) error {
	if err := c.ensureAuthenticated(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	var enabledStr string
	if enabled {
		enabledStr = "1"
	} else {
		enabledStr = "0"
	}

	enableReq := PortEnableRequest{
		Data: PortEnableData{
			Enabled: enabledStr,
		},
	}
	jsonData, err := json.Marshal(enableReq)

	if err != nil {
		return fmt.Errorf("failed to create port enable request: %w", err)
	}

	// port string is 'port'+port number, e.g. 'port1' for port 1
	if port < 1 || port > 8 {
		return fmt.Errorf("invalid port number: %d, must be between 1 and 8", port)
	}
	portStr := fmt.Sprintf("port%d", port)

	url := fmt.Sprintf("https://%s/api/ports_settings/config/%s", c.ipAddr, portStr)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create port enable request: %w", err)
	}

	// Add the Content-Type header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send port enable request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("port enable request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
