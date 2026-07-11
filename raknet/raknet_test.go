package raknet

import "testing"

func TestPingBuildAndDetect(t *testing.T) {
	p := BuildPing(0x1122334455667788, 0x123456789abcdef0)
	if !IsUnconnectedPing(p) {
		t.Fatal("BuildPing output not detected as a ping")
	}
	if got := PingTime(p); got != 0x1122334455667788 {
		t.Fatalf("ping time = %#x, want %#x", got, uint64(0x1122334455667788))
	}
}

func TestPingOpenConnectionsVariantDetected(t *testing.T) {
	p := BuildPing(1, 1)
	p[0] = IDUnconnectedPingOpenConn
	if !IsUnconnectedPing(p) {
		t.Fatal("0x02 (open-connection) ping variant not detected")
	}
}

func TestNonPingNotDetected(t *testing.T) {
	// OpenConnectionRequest1: id 0x07, magic at offset 1 — must NOT read as a ping.
	p := append([]byte{0x07}, Magic[:]...)
	if IsUnconnectedPing(p) {
		t.Fatal("0x07 connection-request falsely detected as ping")
	}
}

func TestPongRoundTrip(t *testing.T) {
	m := DefaultMotd(123)
	pong := BuildPong(0xabcdef, 123, []byte(m.String()))
	p, err := ParsePong(pong)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ServerID != 123 {
		t.Fatalf("serverID = %d, want 123", p.ServerID)
	}
	if !p.MagicOK {
		t.Fatal("magic mismatch in round-tripped pong")
	}
	if p.Motd.ProtocolVersion != "1001" {
		t.Fatalf("proto = %q, want 1001", p.Motd.ProtocolVersion)
	}
}

// TestMotdRoundTripRealBDS pins the format against a real captured BDS pong
// (BDS 1.26.33.1, captured 2026-07-11) so any future drift is caught.
func TestMotdRoundTripRealBDS(t *testing.T) {
	raw := "MCPE;Dedicated Server;1001;1.26.33;0;10;10090977620693818310;Bedrock level;Survival;1;19132;19133;0;1;0;"
	m := ParseMotd(raw)
	if m.Motd != "Dedicated Server" || m.ProtocolVersion != "1001" || m.VersionName != "1.26.33" {
		t.Fatalf("parse wrong: edition=%q motd=%q proto=%q ver=%q",
			m.Edition, m.Motd, m.ProtocolVersion, m.VersionName)
	}
	if len(m.Extras) != 3 {
		t.Fatalf("extras len = %d, want 3 (%v)", len(m.Extras), m.Extras)
	}
	if got := m.String(); got != raw {
		t.Fatalf("round-trip mismatch:\n got: %s\nwant: %s", got, raw)
	}
}

func TestNintendoLimitedPreserved(t *testing.T) {
	// Field 10 value is preserved verbatim ("1" is what BDS/Geyser emit = NOT limited).
	m := ParseMotd("MCPE;a;1001;b;0;10;1;c;Survival;1;19132;19133;")
	if m.NintendoLimited != "1" {
		t.Fatalf("nintendoLimited = %q, want 1", m.NintendoLimited)
	}
}
