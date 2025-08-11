// Copyright 2025 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Methods for configuring an SCC Switch via SSH.

package network

import (
	"fmt"
	"sync"
	"time"
)

const (
	// DS1 is port3
	// DS2 is port5
	// DS3 is port7
	sccDs1Port    = 3
	sccDs2Port    = 5
	sccDs3Port    = 7
	pollPeriodSec = 1
)

type SCCSwitch struct {
	address      string
	username     string
	password     string
	mutex        sync.Mutex
	tsw212Client *TSW212Client
	Status       string

	DriverStationConnections [3]bool
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

func (scc *SCCSwitch) updateDriverStationConnections() {
	scc.mutex.Lock()
	defer scc.mutex.Unlock()
	defaultConnected := [3]bool{true, true, true} // Assume all ports are connected by default.

	if scc.tsw212Client == nil {
		fmt.Println("TSW212Client not initialized, returning default DS connected status")
		scc.DriverStationConnections = defaultConnected
		scc.Status = "ERROR"
		return
	}

	// Get the status of the ports
	portStatus, err := scc.tsw212Client.GetEthernetConnected()
	if err != nil {
		fmt.Printf("failed to get DS ethernet connected status: %v\n", err)
		scc.DriverStationConnections = defaultConnected
		scc.Status = "ERROR"
		return
	}

	scc.DriverStationConnections[0] = portStatus.Port3
	scc.DriverStationConnections[1] = portStatus.Port5
	scc.DriverStationConnections[2] = portStatus.Port7
}

func (scc *SCCSwitch) Run() {
	// set the initial status
	for {
		scc.updateDriverStationConnections()
		time.Sleep(time.Second * pollPeriodSec)
	}
}
