package dns

import (
	"net"
	"strings"
	"testing"
)

// makeQuery builds a minimal DNS A query packet for name.
func makeQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0)             // null terminator
	q = append(q, 0x00, typeA)   // QTYPE=A
	q = append(q, 0x00, classIN) // QCLASS=IN
	return q
}

func TestParseQName(t *testing.T) {
	cases := []string{"play.galaxite.net", "hivebedrock.network", "a.b.c.example.com"}
	for _, name := range cases {
		q := makeQuery(name)
		got, ok := parseQName(q)
		if !ok {
			t.Fatalf("parseQName(%q) not ok", name)
		}
		if got != name {
			t.Fatalf("parseQName = %q, want %q", got, name)
		}
	}
}

func TestBuildAResponse(t *testing.T) {
	ip := net.IPv4(45, 76, 14, 92)
	resp, err := buildAResponse(makeQuery("hivebedrock.network"), ip)
	if err != nil {
		t.Fatalf("buildAResponse: %v", err)
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("response id = %02x%02x, want 1234 (echo query)", resp[0], resp[1])
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("response QR bit not set (not a response)")
	}
	// QDCOUNT=1 at [4:6], ANCOUNT=1 at [6:8].
	if resp[4] != 0 || resp[5] != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", uint16(resp[4])<<8|uint16(resp[5]))
	}
	if resp[6] != 0 || resp[7] != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", uint16(resp[6])<<8|uint16(resp[7]))
	}
	// The A record's RDATA is the final 4 bytes.
	gotIP := net.IP(resp[len(resp)-4:])
	if !gotIP.Equal(ip.To4()) {
		t.Fatalf("answer IP = %s, want %s", gotIP, ip)
	}
}

func TestBuildAResponseRejectsNonIPv4(t *testing.T) {
	if _, err := buildAResponse(makeQuery("x.net"), nil); err == nil {
		t.Fatal("expected error for nil IP")
	}
}

func TestMatchSuffix(t *testing.T) {
	s := &Server{pinned: map[string]net.IP{"hivebedrock.network": net.IPv4(1, 2, 3, 4)}}
	cases := []struct {
		name string
		want bool
	}{
		{"hivebedrock.network", true},
		{"geo.hivebedrock.network", true}, // suffix match (geo load-balancer subdomain)
		{"HIVEBEDROCK.NETWORK", true},     // case-insensitive
		{"evilhivebedrock.network", false},
		{"google.com", false},
	}
	for _, c := range cases {
		_, got := s.match(c.name)
		if got != c.want {
			t.Errorf("match(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// makeAAAAQuery builds a DNS AAAA query for name.
func makeAAAAQuery(name string) []byte {
	q := makeQuery(name)
	q[len(q)-3] = typeAAAA // QTYPE low byte: A(1) -> AAAA(28); high byte already 0
	return q
}

func TestQType(t *testing.T) {
	if got := qType(makeQuery("hivebedrock.network")); got != typeA {
		t.Fatalf("qType(A) = %d, want %d", got, typeA)
	}
	if got := qType(makeAAAAQuery("hivebedrock.network")); got != typeAAAA {
		t.Fatalf("qType(AAAA) = %d, want %d", got, typeAAAA)
	}
}

func TestBuildEmptyResponse(t *testing.T) {
	resp, err := buildEmptyResponse(makeAAAAQuery("hivebedrock.network"))
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatal("id not echoed")
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR bit not set")
	}
	ancount := uint16(resp[6])<<8 | uint16(resp[7])
	if ancount != 0 {
		t.Fatalf("ANCOUNT = %d, want 0 (empty AAAA forces IPv4/A fallback)", ancount)
	}
	qdcount := uint16(resp[4])<<8 | uint16(resp[5])
	if qdcount != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", qdcount)
	}
	echoedQType := uint16(resp[len(resp)-4])<<8 | uint16(resp[len(resp)-3])
	if echoedQType != typeAAAA {
		t.Fatalf("echoed QTYPE = %d, want AAAA(%d)", echoedQType, typeAAAA)
	}
}
