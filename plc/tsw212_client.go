package plc

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

type DsConnections struct {
	Ds1Connected bool
	Ds2Connected bool
	Ds3Connected bool
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

// Get the DS connections (array of 3 bools)
func (c *TSW212Client) GetDSConnections() (DsConnections, error) {
	if c.ipAddr == "" || c.username == "" || c.password == "" {
		// not configured, return early
		return DsConnections{}, nil
	}

	// DS1 is port3
	// DS2 is port5
	// DS3 is port7

	// get the status of the ports
	portsStatus, err := c.getPortStatus()
	if err != nil {
		return DsConnections{}, fmt.Errorf("failed to get port status from ip %s: %w", c.ipAddr, err)
	}

	// find the status of each port using the port ID
	var DS1Status, DS2Status, DS3Status PortStatusData
	for _, port := range portsStatus.Data {
		switch port.Id {
		case "port3": // DS1
			DS1Status = port
		case "port5": // DS2
			DS2Status = port
		case "port7": // DS3
		}
	}

	connections := DsConnections{
		DS1Status.Link == "1",
		DS2Status.Link == "1",
		DS3Status.Link == "1",
	}

	return connections, nil
}
