// Package raknet implements the subset of the RakNet offline protocol needed to
// advertise a Bedrock server on a LAN: the ID_UNCONNECTED_PING / PONG handshake
// and the Bedrock MOTD ("pong userData") format.
//
// Wire format verified 2026-07-11 against pmmp/RakLib, CloudburstMC/Network,
// sandertv/go-raknet, whirvis/JRakNet and facebookarchive/RakNet. See
// docs/reference-bedrock-lan-spoof.md for the byte-exact spec and citations.
package raknet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Magic is the 16-byte RakNet offline constant. Receivers validate it byte-exact.
var Magic = [16]byte{
	0x00, 0xff, 0xff, 0x00,
	0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd,
	0x12, 0x34, 0x56, 0x78,
}

// Offline packet IDs.
const (
	IDUnconnectedPing         = 0x01 // client scanning the server list
	IDUnconnectedPingOpenConn = 0x02 // client intending to connect
	IDUnconnectedPong         = 0x1c
)

const (
	pingHeaderLen = 25 // 1 ID + 8 time + 16 magic — minimum to identify a ping
	pongHeaderLen = 35 // 1 ID + 8 time + 8 serverID + 16 magic + 2 len
)

// magicAt reports whether b[off:off+16] equals Magic.
func magicAt(b []byte, off int) bool {
	return len(b) >= off+16 && bytes.Equal(b[off:off+16], Magic[:])
}

// IsUnconnectedPing reports whether b is an offline ping (0x01 or 0x02) carrying
// the RakNet magic. Both variants are answered with an ID_UNCONNECTED_PONG.
func IsUnconnectedPing(b []byte) bool {
	return len(b) >= pingHeaderLen &&
		(b[0] == IDUnconnectedPing || b[0] == IDUnconnectedPingOpenConn) &&
		magicAt(b, 9)
}

// PingTime returns the 8-byte big-endian timestamp from an offline ping/pong.
func PingTime(b []byte) int64 { return int64(binary.BigEndian.Uint64(b[1:9])) }

// BuildPing constructs an ID_UNCONNECTED_PING (0x01), 33 bytes:
//
//	ID | time(8 BE) | MAGIC(16) | clientGUID(8 BE)
//
// MAGIC sits BETWEEN the two longs.
func BuildPing(timeMs, clientGUID int64) []byte {
	b := make([]byte, 33)
	b[0] = IDUnconnectedPing
	binary.BigEndian.PutUint64(b[1:9], uint64(timeMs))
	copy(b[9:25], Magic[:])
	binary.BigEndian.PutUint64(b[25:33], uint64(clientGUID))
	return b
}

// BuildPong constructs an ID_UNCONNECTED_PONG (0x1c):
//
//	ID | time(8 BE) | serverID(8 BE) | MAGIC(16) | len(2 BE u16) | motd
//
// Note: MAGIC comes AFTER both longs here (asymmetric with the ping).
func BuildPong(timeMs, serverID int64, motd []byte) []byte {
	n := len(motd)
	if n > 0xffff {
		n = 0xffff
		motd = motd[:n]
	}
	b := make([]byte, 0, pongHeaderLen+n)
	var t, g [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(timeMs))
	binary.BigEndian.PutUint64(g[:], uint64(serverID))
	b = append(b, IDUnconnectedPong)
	b = append(b, t[:]...)
	b = append(b, g[:]...)
	b = append(b, Magic[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(n))
	b = append(b, l[:]...)
	b = append(b, motd...)
	return b
}

// Pong is a parsed ID_UNCONNECTED_PONG.
type Pong struct {
	PingTime int64
	ServerID int64
	MagicOK  bool
	Motd     *Motd
}

// ParsePong decodes an ID_UNCONNECTED_PONG datagram.
func ParsePong(b []byte) (*Pong, error) {
	if len(b) < pongHeaderLen {
		return nil, errors.New("pong too short")
	}
	if b[0] != IDUnconnectedPong {
		return nil, fmt.Errorf("not a pong: 0x%02x", b[0])
	}
	p := &Pong{
		PingTime: int64(binary.BigEndian.Uint64(b[1:9])),
		ServerID: int64(binary.BigEndian.Uint64(b[9:17])),
		MagicOK:  magicAt(b, 17),
	}
	ml := int(binary.BigEndian.Uint16(b[33:35]))
	end := 35 + ml
	if end > len(b) {
		end = len(b)
	}
	p.Motd = ParseMotd(string(b[35:end]))
	return p, nil
}

// Motd is the Bedrock "userData" string carried in a pong: ';' delimited,
// terminated by ';'. Field order verified against CloudburstMC BedrockPong.java.
type Motd struct {
	Edition         string   // 1  MCPE
	Motd            string   // 2  line 1
	ProtocolVersion string   // 3  gates connect (client must match)
	VersionName     string   // 4  human version string
	PlayerCount     string   // 5
	MaxPlayers      string   // 6
	ServerID        string   // 7  RakNet GUID (echoed in handshake)
	SubMotd         string   // 8  line 2
	GameType        string   // 9
	NintendoLimited string   // 10 "1" = NOT limited (inverted polarity!)
	IPv4Port        string   // 11 display only
	IPv6Port        string   // 12 display only
	Extras          []string // trailing fields (BDS emits 3)
}

// ParseMotd parses a Bedrock pong MOTD string, preserving trailing fields.
func ParseMotd(s string) *Motd {
	s = strings.TrimSuffix(s, ";")
	p := strings.Split(s, ";")
	get := func(i int, def string) string {
		if i < len(p) {
			return p[i]
		}
		return def
	}
	m := &Motd{
		Edition:         get(0, "MCPE"),
		Motd:            get(1, ""),
		ProtocolVersion: get(2, ""),
		VersionName:     get(3, ""),
		PlayerCount:     get(4, "0"),
		MaxPlayers:      get(5, "10"),
		ServerID:        get(6, ""),
		SubMotd:         get(7, ""),
		GameType:        get(8, "Survival"),
		NintendoLimited: get(9, "1"),
		IPv4Port:        get(10, "19132"),
		IPv6Port:        get(11, "19133"),
	}
	for i := 12; i < len(p); i++ {
		m.Extras = append(m.Extras, p[i])
	}
	return m
}

// String re-encodes the MOTD to its ';' delimited wire form with a trailing ';'.
func (m *Motd) String() string {
	fields := []string{
		m.Edition, m.Motd, m.ProtocolVersion, m.VersionName,
		m.PlayerCount, m.MaxPlayers, m.ServerID, m.SubMotd,
		m.GameType, m.NintendoLimited, m.IPv4Port, m.IPv6Port,
	}
	fields = append(fields, m.Extras...)
	return strings.Join(fields, ";") + ";"
}

// DefaultMotd returns a plausible fallback MOTD (used if the remote is
// unreachable at startup). Defaults reflect Bedrock 1.26.33 / protocol 1001.
func DefaultMotd(serverID int64) *Motd {
	return &Motd{
		Edition:         "MCPE",
		Motd:            "Dedicated Server",
		ProtocolVersion: "1001",
		VersionName:     "1.26.33",
		PlayerCount:     "0",
		MaxPlayers:      "10",
		ServerID:        strconv.FormatInt(serverID, 10),
		SubMotd:         "Bedrock level",
		GameType:        "Survival",
		NintendoLimited: "1",
		IPv4Port:        "19132",
		IPv6Port:        "19133",
	}
}
