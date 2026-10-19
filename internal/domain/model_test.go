package domain

import "testing"

func TestConfigLimits(t *testing.T) {
	valid := ScanConfig{Ports: []uint16{443, 22, 443}, Concurrency: 4, TimeoutMS: 100}
	normalized, err := valid.Normalize(1)
	if err != nil || len(normalized.Ports) != 2 || normalized.Ports[0] != 22 || len(valid.Ports) != 3 {
		t.Fatal(normalized, err)
	}
	for _, tc := range []struct {
		hosts, concurrency, timeout int
		ports                       []uint16
	}{
		{0, 1, 100, []uint16{22}}, {257, 1, 100, []uint16{22}},
		{1, 0, 100, []uint16{22}}, {1, 65, 100, []uint16{22}},
		{1, 1, 9, []uint16{22}}, {1, 1, 30001, []uint16{22}},
		{1, 1, 100, nil}, {1, 1, 100, []uint16{0}},
	} {
		if _, err := (ScanConfig{Ports: tc.ports, Concurrency: tc.concurrency, TimeoutMS: tc.timeout}).Normalize(tc.hosts); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	ports := make([]uint16, 257)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	if _, err := (ScanConfig{Ports: ports, Concurrency: 1, TimeoutMS: 100}).Normalize(256); err == nil {
		t.Fatal("attempt limit ignored")
	}
}
func TestCanonicalIP(t *testing.T) {
	for _, bad := range []string{"", "localhost", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1%en0"} {
		if _, err := CanonicalIP(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
