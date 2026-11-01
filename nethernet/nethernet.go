// Package nethernet implements the subset of Bedrock's NetherNet transport needed
// to relay a console's connection through this proxy without terminating it.
//
// Since Bedrock 26.50 BDS defaults to NetherNet, and since 26.60 clients no longer
// speak RakNet at all. NetherNet is WebRTC: the client signals over plain HTTP on
// TCP <server-port> (GET /v1/join for server info, POST /v1/join/{networkId} with
// an SDP offer, answered with an SDP answer), then runs ICE + DTLS + SCTP over
// UDP to whatever candidate the server's answer advertised.
//
// The proxy relays that without understanding the game: it rewrites the ICE
// candidates in the offer and answer so each side's only candidate is the proxy,
// and routes UDP by the ICE username carried in STUN binding requests. DTLS and
// everything inside it stay end-to-end between console and server, so the
// server's online-mode / Xbox auth and identity assertion are untouched (the
// identity covers DTLS fingerprints, not candidate addresses).
package nethernet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Candidate is one parsed a=candidate line.
type Candidate struct {
	Foundation string
	Component  string
	Transport  string // "UDP" / "udp" / "tcp"
	Priority   string
	IP         string
	Port       int
	Type       string // host, srflx, prflx, relay
}

// SessionDesc is the ICE-relevant part of an SDP blob.
type SessionDesc struct {
	Ufrag      string
	Candidates []Candidate
}

// splitLines splits SDP on CRLF or LF and reports the line ending used.
func splitLines(sdp string) ([]string, string) {
	eol := "\n"
	if strings.Contains(sdp, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(sdp, eol)
	return lines, eol
}

// parseCandidate parses the value after "a=candidate:".
func parseCandidate(v string) (Candidate, bool) {
	f := strings.Fields(v)
	if len(f) < 8 || f[6] != "typ" {
		return Candidate{}, false
	}
	port, err := strconv.Atoi(f[5])
	if err != nil {
		return Candidate{}, false
	}
	return Candidate{
		Foundation: f[0], Component: f[1], Transport: f[2], Priority: f[3],
		IP: f[4], Port: port, Type: f[7],
	}, true
}

// Parse extracts the ICE ufrag and candidates from an SDP blob.
func Parse(sdp string) SessionDesc {
	var d SessionDesc
	lines, _ := splitLines(sdp)
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "a=ice-ufrag:"):
			if d.Ufrag == "" {
				d.Ufrag = strings.TrimPrefix(l, "a=ice-ufrag:")
			}
		case strings.HasPrefix(l, "a=candidate:"):
			if c, ok := parseCandidate(strings.TrimPrefix(l, "a=candidate:")); ok {
				d.Candidates = append(d.Candidates, c)
			}
		}
	}
	return d
}

// PickUDPv4 returns the UDP IPv4 candidate to relay to: one whose IP equals
// prefer if present (the server's own address as we reach it), else the first
// UDP IPv4 candidate. The second return is false if there is none.
func PickUDPv4(cands []Candidate, prefer net.IP) (Candidate, bool) {
	var first *Candidate
	for i := range cands {
		c := &cands[i]
		ip := net.ParseIP(c.IP)
		if !strings.EqualFold(c.Transport, "udp") || ip == nil || ip.To4() == nil {
			continue
		}
		if prefer != nil && ip.Equal(prefer) {
			return *c, true
		}
		if first == nil {
			first = c
		}
	}
	if first == nil {
		return Candidate{}, false
	}
	return *first, true
}

// RewriteCandidates returns sdp with every a=candidate line removed and a single
// UDP host candidate for ip:port inserted where the first one was (or before
// a=end-of-candidates / at the end of the media section if there were none).
// c= connection lines are pointed at ip too, for tidiness.
func RewriteCandidates(sdp string, ip net.IP, port int) string {
	lines, eol := splitLines(sdp)
	cand := fmt.Sprintf("a=candidate:1 1 UDP 2122317823 %s %d typ host", ip, port)
	out := make([]string, 0, len(lines)+1)
	inserted := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "a=candidate:"):
			if !inserted {
				out = append(out, cand)
				inserted = true
			}
			continue
		case strings.HasPrefix(l, "a=end-of-candidates") && !inserted:
			out = append(out, cand)
			inserted = true
		case strings.HasPrefix(l, "c=IN IP4 ") || strings.HasPrefix(l, "c=IN IP6 "):
			l = "c=IN IP4 " + ip.String()
		}
		out = append(out, l)
	}
	if !inserted {
		// No candidate lines at all: append before the trailing empty line.
		at := len(out)
		if at > 0 && out[at-1] == "" {
			at--
		}
		out = append(out[:at], append([]string{cand}, out[at:]...)...)
	}
	return strings.Join(out, eol)
}

// STUN constants (RFC 8489).
const (
	stunHeaderLen   = 20
	stunMagicCookie = 0x2112A442
	stunAttrUser    = 0x0006
)

// IsSTUN reports whether b looks like a STUN message (top two bits zero, magic
// cookie present, length consistent). RakNet and DTLS never match this.
func IsSTUN(b []byte) bool {
	if len(b) < stunHeaderLen || b[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return false
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	return l%4 == 0 && stunHeaderLen+l <= len(b)
}

// STUNUsername returns the USERNAME attribute of a STUN message. In an ICE
// connectivity check it is "<receiver ufrag>:<sender ufrag>".
func STUNUsername(b []byte) (string, bool) {
	if !IsSTUN(b) {
		return "", false
	}
	end := stunHeaderLen + int(binary.BigEndian.Uint16(b[2:4]))
	for off := stunHeaderLen; off+4 <= end; {
		typ := binary.BigEndian.Uint16(b[off : off+2])
		l := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+l > end {
			return "", false
		}
		if typ == stunAttrUser {
			return string(b[off+4 : off+4+l]), true
		}
		off += 4 + (l+3)&^3
	}
	return "", false
}
