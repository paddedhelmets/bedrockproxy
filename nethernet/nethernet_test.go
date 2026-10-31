package nethernet

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

const answer = "v=0\r\n" +
	"o=- 123 2 IN IP4 127.0.0.1\r\n" +
	"s=-\r\n" +
	"t=0 0\r\n" +
	"a=group:BUNDLE 0\r\n" +
	"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
	"c=IN IP4 0.0.0.0\r\n" +
	"a=ice-ufrag:srvU\r\n" +
	"a=ice-pwd:srvpassword\r\n" +
	"a=fingerprint:sha-256 AA:BB\r\n" +
	"a=setup:passive\r\n" +
	"a=candidate:1 1 UDP 2122317823 172.17.0.2 19133 typ host\r\n" +
	"a=candidate:2 1 UDP 2122317567 192.168.41.249 19133 typ host\r\n" +
	"a=candidate:3 1 UDP 2122317567 fe80::1 19133 typ host\r\n" +
	"a=end-of-candidates\r\n"

func TestParse(t *testing.T) {
	d := Parse(answer)
	if d.Ufrag != "srvU" {
		t.Fatalf("ufrag = %q", d.Ufrag)
	}
	if len(d.Candidates) != 3 || d.Candidates[1].IP != "192.168.41.249" || d.Candidates[1].Port != 19133 {
		t.Fatalf("candidates = %+v", d.Candidates)
	}
}

func TestPickUDPv4(t *testing.T) {
	d := Parse(answer)
	c, ok := PickUDPv4(d.Candidates, net.ParseIP("192.168.41.249"))
	if !ok || c.IP != "192.168.41.249" {
		t.Fatalf("preferred pick = %+v %v", c, ok)
	}
	c, ok = PickUDPv4(d.Candidates, net.ParseIP("100.64.0.1"))
	if !ok || c.IP != "172.17.0.2" {
		t.Fatalf("fallback pick = %+v %v", c, ok)
	}
	if _, ok := PickUDPv4(nil, nil); ok {
		t.Fatal("pick from empty should fail")
	}
}

func TestRewriteCandidates(t *testing.T) {
	out := RewriteCandidates(answer, net.ParseIP("192.168.41.248"), 19132)
	if n := strings.Count(out, "a=candidate:"); n != 1 {
		t.Fatalf("want 1 candidate, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "a=candidate:1 1 UDP 2122317823 192.168.41.248 19132 typ host\r\na=end-of-candidates\r\n") {
		t.Fatalf("candidate not placed before end-of-candidates:\n%s", out)
	}
	if !strings.Contains(out, "c=IN IP4 192.168.41.248\r\n") {
		t.Fatalf("c= not rewritten:\n%s", out)
	}
	if !strings.Contains(out, "a=fingerprint:sha-256 AA:BB\r\n") || !strings.Contains(out, "a=ice-pwd:srvpassword\r\n") {
		t.Fatal("unrelated lines must be preserved")
	}
}

func TestRewriteNoCandidates(t *testing.T) {
	in := "v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=ice-ufrag:x\n"
	out := RewriteCandidates(in, net.ParseIP("10.0.0.1"), 5000)
	if !strings.HasSuffix(out, "a=candidate:1 1 UDP 2122317823 10.0.0.1 5000 typ host\n") {
		t.Fatalf("got:\n%q", out)
	}
}

func stunBinding(user string) []byte {
	attr := make([]byte, 4+len(user))
	binary.BigEndian.PutUint16(attr[0:2], stunAttrUser)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(user)))
	copy(attr[4:], user)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	// Trailing PRIORITY attribute to make sure parsing walks past USERNAME.
	attr = append(attr, 0x00, 0x24, 0x00, 0x04, 1, 2, 3, 4)
	b := make([]byte, stunHeaderLen, stunHeaderLen+len(attr))
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	return append(b, attr...)
}

func TestSTUNUsername(t *testing.T) {
	u, ok := STUNUsername(stunBinding("srvU:cliU"))
	if !ok || u != "srvU:cliU" {
		t.Fatalf("username = %q %v", u, ok)
	}
	u, ok = STUNUsername(stunBinding("abc:defgh")) // odd length → padding
	if !ok || u != "abc:defgh" {
		t.Fatalf("padded username = %q %v", u, ok)
	}
}

func TestIsSTUNRejectsOthers(t *testing.T) {
	raknetPing := append([]byte{0x01}, make([]byte, 32)...)
	dtls := append([]byte{0x16, 0xfe, 0xfd}, make([]byte, 30)...)
	for name, b := range map[string][]byte{"raknet": raknetPing, "dtls": dtls, "short": {0, 1}} {
		if IsSTUN(b) {
			t.Errorf("%s misdetected as STUN", name)
		}
	}
}
