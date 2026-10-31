package main

import (
	"fmt"
	"strings"
)

type transportProtocol string

const (
	protocolNetherNet transportProtocol = "nethernet"
	protocolRakNet    transportProtocol = "raknet"
)

func parseTransportProtocol(value string) (transportProtocol, error) {
	switch transportProtocol(strings.ToLower(value)) {
	case protocolNetherNet:
		return protocolNetherNet, nil
	case protocolRakNet:
		return protocolRakNet, nil
	default:
		return "", fmt.Errorf("invalid --protocol %q (want raknet or nethernet)", value)
	}
}
