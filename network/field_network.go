package network

import (
	"fmt"

	"github.com/Team254/cheesy-arena/model"
)

// create enum
type NetworkType int

const (
	CiscoNetwork NetworkType = iota
	UniFiNetwork
)

type FieldNetwork struct {
	networkType NetworkType
	ciscoNetwork *Cisco
	unifiNetwork *UniFi
}

func NewFieldNetwork(address, password string, networkType NetworkType) *FieldNetwork {
	fieldNetwork := &FieldNetwork{
		networkType: networkType,
	}

	switch networkType {
	case CiscoNetwork:
		fieldNetwork.ciscoNetwork = NewCiscoNetwork(address, password)
	case UniFiNetwork:
		fieldNetwork.unifiNetwork = NewUnifiNetwork(address, password)
	default:
		fieldNetwork.networkType = NetworkType(CiscoNetwork)
		fieldNetwork.ciscoNetwork = NewCiscoNetwork(address, password)
	}

	return fieldNetwork
}

func (fn *FieldNetwork) ConfigureTeamEthernet(teams [6]*model.Team) error {
	switch fn.networkType {
	case CiscoNetwork:
		if fn.ciscoNetwork == nil {
			return fmt.Errorf("cisco switch not initialized")
		}
		return fn.ciscoNetwork.configureTeamEthernet(teams)
	case UniFiNetwork:
		if fn.unifiNetwork == nil {
			return fmt.Errorf("cisco switch not initialized")
		}
		return fn.unifiNetwork.configureTeamNetwork(teams)
	default:
		return fmt.Errorf("unsupported network type: %v", fn.networkType)
	}
}

func (fn *FieldNetwork) GetStatus() string {
    switch fn.networkType {
    case CiscoNetwork:
        if fn.ciscoNetwork == nil {
            return "NOT_INITIALIZED"
        }
        return fn.ciscoNetwork.Status
    case UniFiNetwork:
        if fn.unifiNetwork == nil {
            return "NOT_INITIALIZED"
        }
        return fn.unifiNetwork.Status
    default:
        return "UNKNOWN_TYPE"
    }
}