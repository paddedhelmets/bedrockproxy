package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

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

func TestCLI(t *testing.T) {
	if os.Getenv("BEDROCKPROXY_CLI_TEST") == "1" {
		os.Args = append([]string{os.Args[0]}, strings.Split(os.Getenv("BEDROCKPROXY_CLI_ARGS"), " ")...)
		main()
		return
	}
	for _, tc := range []struct{ args, want string }{
		{"--protocol 2169 --dns-listen :53 --dns-target-ip invalid", "--dns-target-ip"},
		{"--dns-listen 127.0.0.1:0 --dns-target-ip ::1", "not a valid IPv4"},
		{"--protocol raknet --remote-signal-url example.com:19132", "--remote-signal-url is only supported"},
		{"--protocol 2169 --protocol-version 123", "conflicts with --protocol-version"},
	} {
		t.Run(tc.args, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestCLI$")
			cmd.Env = append(os.Environ(), "BEDROCKPROXY_CLI_TEST=1", "BEDROCKPROXY_CLI_ARGS="+tc.args)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("error = %v, output = %q; want %q", err, out, tc.want)
			}
		})
	}
}

func TestResolveProtocol(t *testing.T) {
	for _, tc := range []struct {
		protocol, version string
		want              transportProtocol
		wantVersion       string
		wantErr           bool
	}{
		{"nethernet", "", protocolNetherNet, "", false},
		{"raknet", "2169", protocolRakNet, "2169", false},
		{"2169", "", protocolRakNet, "2169", false},
		{"2169", "2169", protocolRakNet, "2169", false},
		{"2169", "123", "", "", true},
		{"invalid", "", "", "", true},
	} {
		got, version, err := resolveProtocol(tc.protocol, tc.version)
		if (err != nil) != tc.wantErr || got != tc.want || version != tc.wantVersion {
			t.Errorf("resolveProtocol(%q, %q) = %q, %q, %v", tc.protocol, tc.version, got, version, err)
		}
	}
}
