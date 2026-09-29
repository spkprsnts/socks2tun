package control

import (
	"net/netip"
	"slices"
	"testing"
)

func TestApply(t *testing.T) {
	base := Config{MTU: 1280}
	ip := netip.MustParseAddr
	cases := []struct {
		line string
		want Config
		err  bool
	}{
		{"ip 10.0.0.2", Config{IP: ip("10.0.0.2"), MTU: 1280}, false},
		{"ip 10.0.0.2/32", Config{IP: ip("10.0.0.2"), MTU: 1280}, false},
		{"IP 10.0.0.2", Config{IP: ip("10.0.0.2"), MTU: 1280}, false},
		{"dns 1.1.1.1,8.8.8.8", Config{DNS: []netip.Addr{ip("1.1.1.1"), ip("8.8.8.8")}, MTU: 1280}, false},
		{"dns 1.1.1.1 8.8.8.8", Config{DNS: []netip.Addr{ip("1.1.1.1"), ip("8.8.8.8")}, MTU: 1280}, false},
		{"mtu 1400", Config{MTU: 1400}, false},
		{"ip 10.0.0.2 dns 1.1.1.1 mtu 1300", Config{IP: ip("10.0.0.2"), DNS: []netip.Addr{ip("1.1.1.1")}, MTU: 1300}, false},
		{"[КЛИЕНТ] Tunnel IP: 10.8.0.5/32 | DNS: 10.8.0.1", Config{IP: ip("10.8.0.5"), DNS: []netip.Addr{ip("10.8.0.1")}, MTU: 1280}, false},
		{"ip 10.0.0.0/24", base, true},
		{"ip 2001:db8::1", base, true},
		{"ip 0.0.0.0", base, true},
		{"ip", base, true},
		{"dns 1.1.1.1,bogus", base, true},
		{"mtu 100", base, true},
		{"mtu 70000", base, true},
		{"route 1.2.3.4", base, true},
	}
	for _, tc := range cases {
		got, ok, err := Apply(base, tc.line)
		if (err != nil) != tc.err {
			t.Errorf("%q: err = %v, want error %v", tc.line, err, tc.err)
			continue
		}
		if !ok {
			t.Errorf("%q: not recognised as a command", tc.line)
		}
		if got.IP != tc.want.IP || got.MTU != tc.want.MTU || !slices.Equal(got.DNS, tc.want.DNS) {
			t.Errorf("%q: got %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestApplyKeepsAndClears(t *testing.T) {
	cur := Config{IP: netip.MustParseAddr("10.0.0.2"), DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, MTU: 1280}
	for _, line := range []string{"", "   ", "# comment"} {
		if got, ok, err := Apply(cur, line); ok || err != nil || got.IP != cur.IP {
			t.Errorf("%q: ok=%v err=%v", line, ok, err)
		}
	}
	got, _, _ := Apply(cur, "mtu 1400")
	if got.IP != cur.IP || len(got.DNS) != 1 {
		t.Errorf("mtu command changed other fields: %v", got)
	}
	got, _, _ = Apply(cur, "ip none")
	if got.IP.IsValid() {
		t.Errorf("ip none did not clear the address: %v", got)
	}
	got, _, _ = Apply(cur, "dns none")
	if len(got.DNS) != 0 {
		t.Errorf("dns none did not clear servers: %v", got)
	}
}

func TestString(t *testing.T) {
	c := Config{IP: netip.MustParseAddr("10.0.0.2"), DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, MTU: 1280}
	if got, want := c.String(), "address 10.0.0.2/32 dns 1.1.1.1,8.8.8.8 mtu 1280"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := (Config{MTU: 1400}).String(), "address none dns none mtu 1400"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
