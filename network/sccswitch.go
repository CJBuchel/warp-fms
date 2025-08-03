// Copyright 2025 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Methods for configuring an SCC Switch via SSH.

package network

import (
	"fmt"
	"sync"
)

const (
	// DS1 is port3
	// DS2 is port5
	// DS3 is port7
	sccDs1Port = 3
	sccDs2Port = 5
	sccDs3Port = 7
)

type SCCSwitch struct {
	address      string
	username     string
	password     string
	mutex        sync.Mutex
	tsw212Client *TSW212Client
	Status       string
}

func NewSCCSwitch(address, username, password string) *SCCSwitch {
	return &SCCSwitch{
		address:      address,
		username:     username,
		password:     password,
		tsw212Client: NewTSW212Client(address, password),
		Status:       "UNKNOWN",
	}
}

func (scc *SCCSwitch) SetTeamEthernetEnabled(enabled bool) error {
	scc.mutex.Lock()
	defer scc.mutex.Unlock()

	scc.Status = "CONFIGURING"

	err := scc.tsw212Client.SetPortEnabled(sccDs1Port, enabled)
	if err != nil {
		scc.Status = "ERROR"
		return fmt.Errorf("failed to set port 3 enabled state: %w", err)
	}

	err = scc.tsw212Client.SetPortEnabled(sccDs2Port, enabled)
	if err != nil {
		scc.Status = "ERROR"
		return fmt.Errorf("failed to set port 5 enabled state: %w", err)
	}

	err = scc.tsw212Client.SetPortEnabled(sccDs3Port, enabled)
	if err != nil {
		scc.Status = "ERROR"
		return fmt.Errorf("failed to set port 7 enabled state: %w", err)
	}

	if enabled {
		scc.Status = "ACTIVE"
	} else {
		scc.Status = "DISABLED"
	}

	return nil
}

func (scc *SCCSwitch) GetEthernetConnected() [3]bool {
	defaultConnected := [3]bool{true, true, true} // Assume all ports are connected by default.

	if scc.tsw212Client == nil {
		fmt.Println("TSW212Client not initialized, returning default DS connected status")
		return defaultConnected
	}

	// Get the status of the ports
	portStatus, err := scc.tsw212Client.GetEthernetConnected()
	if err != nil {
		fmt.Printf("failed to get DS ethernet connected status: %v\n", err)
		return defaultConnected // Return default connected status if there's an error.
	}

	if len(portStatus) < 3 {
		fmt.Println("Unexpected port status length, returning default DS connected status")
		return defaultConnected // Return default if the length is unexpected.
	}

	return [3]bool{portStatus[sccDs1Port], portStatus[sccDs2Port], portStatus[sccDs3Port]} // DS1, DS2, DS3
}
