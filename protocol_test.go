package main

import "testing"

func TestParseTransportProtocol(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want transportProtocol
	}{
		{name: "default", in: "nethernet", want: protocolNetherNet},
		{name: "legacy", in: "RAKNET", want: protocolRakNet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTransportProtocol(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTransportProtocolRejectsOldNumericFlagValue(t *testing.T) {
	if _, err := parseTransportProtocol("2169"); err == nil {
		t.Fatal("numeric protocol override must use --protocol-version")
	}
}
