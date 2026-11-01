// Package dns implements a minimal UDP DNS server that pins a set of domains to a
// fixed IP and forwards all other queries verbatim to an upstream resolver.
//
// DNS pinning can be used independently of the relay transport. It does not
// establish compatibility with any particular client or signaling protocol.
//
// It is intentionally dependency-free and UDP-only — sufficient for an A-record
// hijack plus blind byte-for-forwarding. Only IPv4 (A) records are pinned.
package dns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	headerLen = 12
	typeA     = 1
	typeAAAA  = 28
	classIN   = 1
	pinnedTTL = 60

	forwardTimeout = 3 * time.Second
	bufLen         = 65535
)

// DefaultPinnedDomains are the Minecraft Bedrock "Featured Server" hostnames a
// Switch resolves when opening the Servers tab (from BedrockConnect's
// install-bind.sh). CubeCraft is deliberately excluded — it opts out of redirect.
var DefaultPinnedDomains = []string{
	"hivebedrock.network",
	"play.inpvp.net",
	"mco.lbsg.net",
	"play.galaxite.net",
	"play.enchanted.gg",
}

// Server is a minimal UDP DNS server.
type Server struct {
	conn     *net.UDPConn
	pc       *ipv4.PacketConn  // wraps conn; lets us reply from the addressed IP on multi-homed hosts
	pinned   map[string]net.IP // lowercased domain -> IPv4
	upstream *net.UDPAddr
	log      *log.Logger
}

// New binds the UDP listen socket. domains are pinned (exact or suffix match) to
// targetIP; everything else is forwarded to upstream (default 1.1.1.1:53).
func New(listenAddr string, targetIP net.IP, domains []string, upstream string, logger *log.Logger) (*Server, error) {
	if targetIP.To4() == nil {
		return nil, errors.New("dns target IP must be IPv4")
	}
	if logger == nil {
		logger = log.Default()
	}
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	up, err := net.ResolveUDPAddr("udp4", upstream)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream %q: %w", upstream, err)
	}
	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen %q: %w", listenAddr, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen dns %s: %w", listenAddr, err)
	}
	pinned := make(map[string]net.IP, len(domains))
	for _, d := range domains {
		pinned[normalize(d)] = targetIP.To4()
	}
	return &Server{conn: conn, pinned: pinned, upstream: up, log: logger}, nil
}

func normalize(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// Serve runs the query loop until ctx is cancelled or a fatal read error occurs.
func (s *Server) Serve(ctx context.Context) error {
	s.log.Printf("dns server up on %s: pinning %d domain(s) -> %s, forwarding rest to %s",
		s.conn.LocalAddr(), len(s.pinned), s.firstPinnedIP(), s.upstream)
	// Enable IP_PKTINFO so replies can be sourced from the exact local address a
	// client targeted. Required on multi-homed hosts (e.g. a Pi on wifi + ethernet):
	// without it the kernel's route-chosen source can differ from the addressed IP,
	// and the client drops the mismatched reply.
	s.pc = ipv4.NewPacketConn(s.conn)
	if err := s.pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		s.log.Printf("warning: IP_PKTINFO unavailable; multi-homed reply-source fix inactive: %v", err)
	}
	// Close the socket on shutdown so the read below unblocks and the process
	// exits cleanly on Ctrl-C / SIGTERM.
	go func() {
		<-ctx.Done()
		s.log.Printf("dns shutting down...")
		s.conn.Close()
	}()
	buf := make([]byte, bufLen)
	for {
		n, cm, src, err := s.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dns read: %w", err)
		}
		client := src.(*net.UDPAddr)
		var dst net.IP
		var ifx int
		if cm != nil {
			dst = cm.Dst
			ifx = cm.IfIndex
		}
		// Forwarding may block on the upstream, so handle each query concurrently.
		go s.handle(append([]byte(nil), buf[:n]...), client, dst, ifx)
	}
}

// reply sends b to client, sourced from localIP when IP_PKTINFO is available
// (so the reply comes from the address the client actually targeted).
func (s *Server) reply(b []byte, client *net.UDPAddr, localIP net.IP, ifIndex int) {
	if len(localIP) != 0 {
		// Force the source IP to the address the client targeted (IP_PKTINFO); let
		// the kernel route to the client normally.
		_, _ = s.pc.WriteTo(b, &ipv4.ControlMessage{Src: localIP}, client)
	} else {
		_, _ = s.conn.WriteToUDP(b, client)
	}
}

func (s *Server) handle(query []byte, client *net.UDPAddr, localIP net.IP, ifIndex int) {
	name, ok := parseQName(query)
	if !ok {
		s.forward(query, client, localIP, ifIndex)
		return
	}
	ip, hit := s.match(name)
	if !hit {
		s.forward(query, client, localIP, ifIndex)
		return
	}
	// Pinned domain. Answer A with our IP. For AAAA, return an empty answer so
	// IPv6-capable resolvers fall back to A — the proxy is IPv4-only, and without
	// this an AAAA query leaks to a real resolver and the client can reach the
	// genuine server over IPv6, bypassing the redirect.
	switch qType(query) {
	case typeA:
		resp, err := buildAResponse(query, ip)
		if err != nil {
			s.log.Printf("dns build for %q: %v", name, err)
			return
		}
		s.reply(resp, client, localIP, ifIndex)
	case typeAAAA:
		if resp, err := buildEmptyResponse(query); err == nil {
			s.reply(resp, client, localIP, ifIndex)
		}
	default:
		s.forward(query, client, localIP, ifIndex)
	}
}

// qType returns the query's QTYPE (1=A, 28=AAAA, ...), or 0 if unparseable.
func qType(q []byte) uint16 {
	end, ok := questionEnd(q)
	if !ok || end < 4 {
		return 0
	}
	return uint16(q[end-4])<<8 | uint16(q[end-3])
}

// buildEmptyResponse echoes the query's question with zero answer records
// (NOERROR, no answers) — used for AAAA on pinned domains so IPv6-capable
// resolvers fall back to the A record.
func buildEmptyResponse(query []byte) ([]byte, error) {
	end, ok := questionEnd(query)
	if !ok {
		return nil, errors.New("could not parse question")
	}
	opcodeRD := query[2] & 0x79
	resp := make([]byte, 0, end)
	resp = append(resp, query[0:2]...)           // id
	resp = append(resp, 0x80|opcodeRD, 0x80)     // QR=1, copy OPCODE+RD; RA=1, rcode=0
	resp = append(resp, 0x00, 0x01)              // QDCOUNT=1
	resp = append(resp, 0x00, 0x00)              // ANCOUNT=0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)  // NSCOUNT=0, ARCOUNT=0
	resp = append(resp, query[headerLen:end]...) // echo the question
	return resp, nil
}

// match returns the pinned IP for name (exact match, or any parent suffix).
func (s *Server) match(name string) (net.IP, bool) {
	name = normalize(name)
	if ip, ok := s.pinned[name]; ok {
		return ip, true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if ip, ok := s.pinned[name[i+1:]]; ok {
				return ip, true
			}
		}
	}
	return nil, false
}

func (s *Server) forward(query []byte, client *net.UDPAddr, localIP net.IP, ifIndex int) {
	up, err := net.DialUDP("udp4", nil, s.upstream)
	if err != nil {
		s.log.Printf("dns forward dial: %v", err)
		return
	}
	defer up.Close()
	if err := up.SetReadDeadline(time.Now().Add(forwardTimeout)); err != nil {
		return
	}
	if _, err := up.Write(query); err != nil {
		return
	}
	resp := make([]byte, bufLen)
	n, err := up.Read(resp)
	if err != nil {
		return
	}
	s.reply(resp[:n], client, localIP, ifIndex)
}

// parseQName extracts the queried domain name from the first question of a DNS query.
func parseQName(q []byte) (string, bool) {
	if len(q) < headerLen+5 {
		return "", false
	}
	var name []byte
	pos := headerLen
	for {
		if pos >= len(q) {
			return "", false
		}
		l := int(q[pos])
		if l == 0 {
			break
		}
		if l&0xc0 != 0 { // compression pointer not expected in a query question
			return "", false
		}
		if pos+1+l > len(q) {
			return "", false
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, q[pos+1:pos+1+l]...)
		pos += 1 + l
	}
	return string(name), len(name) > 0
}

// buildAResponse constructs a DNS A response for query, answering with ip.
func buildAResponse(query []byte, ip net.IP) ([]byte, error) {
	ip = ip.To4()
	if ip == nil {
		return nil, errors.New("pinned IP is not IPv4")
	}
	end, ok := questionEnd(query)
	if !ok {
		return nil, errors.New("could not parse question")
	}
	id := query[0:2]
	// Header byte 2: QR=1, copy OPCODE+RD, clear AA/TC. Byte 3: RA=1, rcode=0.
	opcodeRD := query[2] & 0x79
	resp := make([]byte, 0, end+16)
	resp = append(resp, id...)
	resp = append(resp, 0x80|opcodeRD, 0x80)
	resp = append(resp, 0x00, 0x01)              // QDCOUNT=1
	resp = append(resp, 0x00, 0x01)              // ANCOUNT=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)  // NSCOUNT=0, ARCOUNT=0
	resp = append(resp, query[headerLen:end]...) // echo the question
	// Answer: name pointer to offset 12, type A, class IN, TTL, RDLEN=4, address.
	resp = append(resp, 0xc0, 0x0c)
	resp = append(resp, 0x00, typeA)
	resp = append(resp, 0x00, classIN)
	resp = append(resp, 0x00, 0x00, 0x00, pinnedTTL)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip...)
	return resp, nil
}

// questionEnd returns the offset just past the first question (QNAME + QTYPE + QCLASS).
func questionEnd(q []byte) (int, bool) {
	pos := headerLen
	for {
		if pos >= len(q) {
			return 0, false
		}
		l := int(q[pos])
		if l == 0 {
			pos++ // null label terminator
			break
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		pos += 1 + l
	}
	end := pos + 4 // QTYPE(2) + QCLASS(2)
	if end > len(q) {
		return 0, false
	}
	return end, true
}

func (s *Server) firstPinnedIP() net.IP {
	for _, ip := range s.pinned {
		return ip
	}
	return nil
}
