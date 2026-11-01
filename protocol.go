package main

import (
	"fmt"
	"strconv"
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

// A numeric --protocol was historically the RakNet MOTD protocol override.
func resolveProtocol(value, version string) (transportProtocol, string, error) {
	if _, err := strconv.ParseUint(value, 10, 32); err == nil {
		if version != "" && version != value {
			return "", "", fmt.Errorf("numeric --protocol conflicts with --protocol-version")
		}
		return protocolRakNet, value, nil
	}
	transport, err := parseTransportProtocol(value)
	return transport, version, err
}
