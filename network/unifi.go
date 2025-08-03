package network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/Team254/cheesy-arena/model"
)

type UniFi struct {
	address string
	password string
	csrfToken string
	mutex sync.Mutex
	configBackoffDuration time.Duration
	configPauseDuration time.Duration
	Status string
}

var UdmIpAddress = "10.0.100.1" // The UDM is the gateway router
var authRoute = "api/auth"
var defaultRoute = "proxy/network/api/s/default"
var restRoute = fmt.Sprintf("%s/rest", defaultRoute)
var statRoute = fmt.Sprintf("%s/stat", defaultRoute)

func NewUnifiNetwork(address, password string) *UniFi {
	return &UniFi{
		address:                 address,
		password:                password,
		configBackoffDuration:   1 * time.Second,
		configPauseDuration:     1 * time.Second,
		Status:                  "UNKNOWN",
	}
}

// Login for the UDM Router
func (ubnt *UniFi) login(client *http.Client) error {
	// Create login request
	loginData := map[string]string{
		"username": "root", // Replace with your username
		"password": ubnt.password, // Replace with your password
	}
	jsonData, _ := json.Marshal(loginData)
	
	req, _ := http.NewRequest("POST", 
		fmt.Sprintf("https://%s/%s/login", ubnt.address, authRoute), 
		bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	// Send login request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Check for success
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Get CSRF token from response header
	csrfToken := resp.Header.Get("X-CSRF-Token")
	// Set network token
	ubnt.csrfToken = csrfToken
	return nil
}

func (ubnt *UniFi) getNetworkID(client *http.Client, vlanID int) (string, error) {
	// Create request to get networks
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/%s/networkconf", ubnt.address, restRoute), nil)
	req.Header.Set("X-CSRF-Token", ubnt.csrfToken)
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return "", err
	}
	defer resp.Body.Close()
	
	// Check for success
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get networks with status %d", resp.StatusCode)
	}

	// Read the response body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	
	// Parse response - first as a generic map to see the structure
	var responseObj map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseObj); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	// Find the network with the specified VLAN ID
	for _, network := range responseObj["data"].([]interface{}) {
		networkMap := network.(map[string]interface{})

		if networkMap["vlan"] != nil && networkMap["vlan"].(float64) == float64(vlanID) {
			return networkMap["_id"].(string), nil
		}
	}

	// If not found, return an error
	return "", fmt.Errorf("network with VLAN ID %d not found", vlanID)
}

type TeamNetworkConfig struct {
	networkID string
	enabled bool
	vlan int
	dhcpIP string // DHCP IP address e.g 10.47.88.1
}

func (ubnt *UniFi) updateTeamNetwork(client *http.Client, teamConfig TeamNetworkConfig) error {

	// split the dhcpIP into parts and replace last part with 50
	dhcpParts := strings.Split(teamConfig.dhcpIP, ".")
	if len(dhcpParts) != 4 {
		return fmt.Errorf("invalid DHCP IP address format: %s", teamConfig.dhcpIP)
	}
	gateway_address := strings.Join(dhcpParts[:3], ".") + ".4" // Set the last part to 4
	dhcp_start := strings.Join(dhcpParts[:3], ".") + ".50" // Set the last part to 50
	dhcp_stop := strings.Join(dhcpParts[:3], ".") + ".200" // Set the last part to 254

	// Network configuration data
	networkConfig := map[string]interface{}{
		"vlan_enabled":   true,
		"vlan":           teamConfig.vlan,
		"ip_subnet":      teamConfig.dhcpIP+"/24",
		"dhcpd_enabled":  true,
		"dhcpd_start":    dhcp_start,
		"dhcpd_stop":     dhcp_stop,
		"enabled":        teamConfig.enabled,
		"gateway":        gateway_address,
	}
	jsonData, _ := json.Marshal(networkConfig)

	// Create update request
	url := fmt.Sprintf("https://%s/%s/networkconf/%s", ubnt.address, restRoute, teamConfig.networkID)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", ubnt.csrfToken)

	// Send update request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for success
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (ubnt *UniFi) getDeviceStatus(client *http.Client) (bool, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/%s/device", ubnt.address, statRoute), nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", ubnt.csrfToken)

	// Sendrequest
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error getting device status: %w", err)
	}
	defer resp.Body.Close()

	// Check for success
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to get device status with status %d", resp.StatusCode)
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("error parsing device status response: %w", err)
	}

	// Extract device statuses
	devices, ok := result["data"].([]interface{})

	if !ok {
		return false, fmt.Errorf("unexpected data format in device status")
	}

	for _, dev := range devices {
		device, ok := dev.(map[string]interface{})
		if !ok {
			fmt.Print("Skipping status check (unknown issue)")
			continue
		}

		// 0 = Disconnected/Offline
		// 1 = Connected/Online
		// 2 = Pending Adoption
		// 3 = Adopting
		// 4 = Adoption Failed/Heartbeat Missed
		// 5 = Provisioning ("Getting Ready")
		// 6 = Managed (Fully Ready/Configured)

		// print line by line
		if device["type"] == "udm" {
			state := int(device["state"].(float64))
			successful := device["last_config_applied_successfully"].(bool)
			if state == 1 && successful { // json decodes numbers as float64
				return true, nil
			}
		}
	}

	return false, nil
}

func (ubnt *UniFi) configureTeamNetwork(teams [6]*model.Team) error {
	// Lock the mutex to prevent concurrent access
	ubnt.mutex.Lock()
	defer ubnt.mutex.Unlock()
	ubnt.Status = "CONFIGURING"

	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Println("Error creating cookie jar:", err)
		ubnt.Status = "ERROR"
	}

	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Log into the UDM router
	if err := ubnt.login(client); err != nil {
		fmt.Println("Error logging in:", err)
		ubnt.Status = "ERROR"
		return err
	}

	// Set team networks to disabled with default DHCP IPs
	for vlan := 10; vlan <= 60; vlan += 10 {
		networkID, err := ubnt.getNetworkID(client, vlan)
		if err != nil {
			fmt.Println("Error getting network ID:", err)
			ubnt.Status = "ERROR"
			return err
		}

		teamConfig := TeamNetworkConfig{
			networkID: networkID,
			enabled:   false,
			vlan:      vlan,
			dhcpIP:    fmt.Sprintf("10.0.%d.4", vlan),
		}
		if err := ubnt.updateTeamNetwork(client, teamConfig); err != nil {
			fmt.Println("Error updating team network:", err)
			ubnt.Status = "ERROR"
			return err
		}
	}

	// Set the team networks
	setTeamNetwork := func(team *model.Team, vlan int) error {
		if team == nil {
			return nil
		}
		teamPartialIp := fmt.Sprintf("%d.%d", team.Id/100, team.Id%100)
		dhcpIP := fmt.Sprintf("10.%s.4", teamPartialIp)
		networkID, err := ubnt.getNetworkID(client, vlan)
		if err != nil {
			fmt.Println("Error getting network ID:", err)
			ubnt.Status = "ERROR"
			return err
		}
		teamConfig := TeamNetworkConfig{
			networkID: networkID,
			enabled:   true,
			vlan:      vlan,
			dhcpIP:    dhcpIP,
		}
		if err := ubnt.updateTeamNetwork(client, teamConfig); err != nil {
			fmt.Println("Error updating team network:", err)
			ubnt.Status = "ERROR"
			return err
		}

		// print the status of the update for team
		fmt.Printf("Team %d VLAN %d Gateway: %s\n", team.Id, vlan, dhcpIP)
		return nil
	}

	for i, team := range teams {
		vlan := 10 * (i + 1)
		if team == nil {
			continue
		}
		fmt.Printf("Configuring team %d with VLAN %d\n", team.Id, 10*(i+1))
		if err := setTeamNetwork(team, vlan); err != nil {
			fmt.Println("Error setting team network:", err)
			ubnt.Status = "ERROR"
			return err
		}
	}

	// // wait for unifi to process the changes
	time.Sleep(time.Second * 1)

	// timeout
	timeout := time.Now().Add(30 * time.Second)
	
	// loop and check device status
	for time.Now().Before(timeout) {
		online, err := ubnt.getDeviceStatus(client)
		if err != nil {
			fmt.Println("Error getting device status:", err)
			ubnt.Status = "ERROR"
			return err
		}
		if online {
			fmt.Println("Network config complete")
			ubnt.Status = "ACTIVE"
			return nil
		} else {
			ubnt.Status = "CONFIGURING"
		}
		time.Sleep(time.Second)
	}

	// If we reach here, the device is not online
	fmt.Println("Network config timeout")
	ubnt.Status = "ERROR"
	return fmt.Errorf("network config timeout")
}