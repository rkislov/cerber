// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/flowexport"
	"github.com/rkislov/cerber/internal/sflow"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SensorEnvelope retains the original message and the transport peer separately
// from addresses claimed inside that message. The enrolled sensor is the observer,
// never automatically the owner of either endpoint.
type SensorEnvelope struct {
	Flow      *flowexport.Evidence `json:"flow,omitempty"`
	PeerPort  uint16               `json:"peer_port,omitempty"`
	Input     string               `json:"input"`
	Peer      string               `json:"peer"`
	Transport string               `json:"transport"`
	Profile   string               `json:"profile"`
	Line      string               `json:"line,omitempty"`
	Packet    []byte               `json:"packet,omitempty"`
	Record    int                  `json:"record,omitempty"`
}

type NetworkObservation struct {
	Sampled           bool       `json:"sampled,omitempty"`
	ReportedAgent     string     `json:"reported_agent,omitempty"`
	SamplePool        uint32     `json:"sample_pool,omitempty"`
	SampleDrops       uint32     `json:"sample_drops,omitempty"`
	SourceIndex       uint32     `json:"source_index,omitempty"`
	SourceType        uint32     `json:"source_type,omitempty"`
	ExporterPort      uint16     `json:"exporter_port,omitempty"`
	ObservationDomain uint32     `json:"observation_domain,omitempty"`
	TemplateID        uint16     `json:"template_id,omitempty"`
	TemplateHash      string     `json:"template_hash,omitempty"`
	ExportSequence    uint32     `json:"export_sequence,omitempty"`
	Kind              string     `json:"kind"`
	Input             string     `json:"input"`
	Exporter          string     `json:"exporter"`
	Transport         string     `json:"transport"`
	ReportedHost      string     `json:"reported_host,omitempty"`
	Application       string     `json:"application,omitempty"`
	Protocol          int        `json:"protocol,omitempty"`
	SourcePort        int        `json:"source_port,omitempty"`
	FlowID            string     `json:"flow_id,omitempty"`
	Start             *time.Time `json:"start,omitempty"`
	End               *time.Time `json:"end,omitempty"`
	Packets           uint64     `json:"packets,omitempty"`
	Bytes             uint64     `json:"bytes,omitempty"`
	InputInterface    int        `json:"input_interface,omitempty"`
	OutputInterface   int        `json:"output_interface,omitempty"`
	SamplingMode      int        `json:"sampling_mode,omitempty"`
	SamplingInterval  int        `json:"sampling_interval,omitempty"`
	Signature         string     `json:"signature,omitempty"`
	Severity          int        `json:"severity,omitempty"`
	TimeBasis         string     `json:"time_basis"`
}

func SensorSource(s string) bool {
	return s == "network:syslog" || s == "network:netflow" || s == "network:suricata"
}

func normalizeSensor(r RawRecord, n Normalized) Normalized {
	n.Parser = "network-sensor/1"
	n.Class = "network_device"
	bad := func() Normalized {
		n.Status = "quarantine"
		n.Class = "unknown"
		n.Message = "Invalid or unsupported network sensor record"
		n.EventTime = r.ReceivedAt
		n.Network = nil
		n.SourceIP = ""
		n.DestinationIP = ""
		n.DestinationPort = 0
		return n
	}
	var v SensorEnvelope
	if json.Unmarshal(r.Raw.Data, &v) != nil || !AgentIdentifier(v.Input) {
		return bad()
	}
	if v.Transport == "file" {
		if v.Peer != "local" {
			return bad()
		}
	} else {
		if v.Transport != "udp" && v.Transport != "tcp" && v.Transport != "tls" {
			return bad()
		}
		ip, e := netip.ParseAddr(v.Peer)
		if e != nil || ip.Zone() != "" {
			return bad()
		}
		v.Peer = ip.Unmap().String()
	}
	n.Network = &NetworkObservation{Kind: v.Profile, Input: v.Input, Exporter: v.Peer, Transport: v.Transport, TimeBasis: "sensor_receive_time"}
	n.Device = v.Peer
	if r.Raw.Source == "network:netflow" && v.Profile == "sflow5" {
		if v.Transport != "udp" || v.PeerPort == 0 {
			return bad()
		}
		samples, e := sflow.Decode(v.Packet)
		if e != nil || v.Record < 0 || v.Record >= len(samples) {
			return bad()
		}
		f := samples[v.Record]
		o := n.Network
		o.Sampled = true
		o.ReportedAgent = f.Agent
		o.ExporterPort = v.PeerPort
		o.ObservationDomain = f.SubAgent
		o.ExportSequence = f.Sequence
		o.SourceIndex = f.SourceIndex
		o.SourceType = f.SourceType
		o.SamplePool = f.Pool
		o.SampleDrops = f.Drops
		o.SamplingInterval = int(f.Rate)
		o.SourcePort = f.SourcePort
		o.Protocol = f.Protocol
		if f.InputFormat == 0 && f.Input != 0x3fffffff {
			o.InputInterface = int(f.Input)
		}
		if f.OutputFormat == 0 && f.Output != 0x3fffffff {
			o.OutputInterface = int(f.Output)
		}
		n.Product = "sFlow v5"
		n.Action = "flow_metadata"
		n.Message = "sFlow sample metadata; unsupported records retained in original datagram"
		if f.Source != "" && f.Destination != "" {
			n.SourceIP = f.Source
			n.DestinationIP = f.Destination
			n.DestinationPort = f.DestinationPort
			n.Class = "network_flow"
			n.Action = "flow_observed"
			o.Packets = 1
			o.Bytes = uint64(f.Length)
			n.Message = "Sampled packet observation; counts are not extrapolated"
		}
	} else if r.Raw.Source == "network:netflow" && (v.Profile == "netflow9" || v.Profile == "ipfix") {
		if v.Transport != "udp" || v.PeerPort == 0 || v.Flow == nil {
			return bad()
		}
		f, e := flowexport.DecodeEvidence(*v.Flow)
		if e != nil || v.Profile == "netflow9" && f.Header.Version != 9 || v.Profile == "ipfix" && f.Header.Version != 10 {
			return bad()
		}
		if f.Header.Exported.After(r.ReceivedAt.Add(5 * time.Minute)) {
			return bad()
		}
		o := n.Network
		o.ExporterPort = v.PeerPort
		o.ObservationDomain = f.Header.Domain
		o.TemplateID = f.TemplateID
		o.TemplateHash = f.TemplateHash
		o.ExportSequence = f.Header.Sequence
		n.SourceIP = f.Source
		n.DestinationIP = f.Destination
		n.DestinationPort = f.DestinationPort
		o.Protocol = f.Protocol
		o.SourcePort = f.SourcePort
		o.Start = f.Start
		o.End = f.End
		o.Packets = f.Packets
		o.Bytes = f.Bytes
		o.FlowID = f.ID
		o.InputInterface = f.Input
		o.OutputInterface = f.Output
		o.SamplingMode = f.SamplingMode
		o.SamplingInterval = f.SamplingInterval
		o.TimeBasis = f.TimeBasis
		n.EventTime = f.Header.Exported
		if f.End != nil {
			n.EventTime = *f.End
		}
		n.Product = map[string]string{"netflow9": "NetFlow v9", "ipfix": "IPFIX"}[v.Profile]
		n.Message = "Exported flow metadata; template snapshot retained"
		if !f.Options && f.Source != "" && f.Destination != "" {
			n.Class = "network_flow"
			n.Action = "flow_observed"
		} else {
			n.Action = "flow_metadata"
			n.Message = "Export metadata / options (not an endpoint connection)"
		}
	} else if r.Raw.Source == "network:netflow" {
		if v.Profile != "netflow5" || v.Transport != "udp" {
			return bad()
		}
		flows, e := DecodeNetFlow5(v.Packet)
		if e != nil || v.Record < 0 || v.Record >= len(flows) {
			return bad()
		}
		f := flows[v.Record]
		o := n.Network
		n.SourceIP = f.Source
		n.DestinationIP = f.Destination
		n.DestinationPort = f.DestinationPort
		o.Protocol = f.Protocol
		o.SourcePort = f.SourcePort
		o.Start = &f.Start
		o.End = &f.End
		o.Packets = f.Packets
		o.Bytes = f.Bytes
		o.FlowID = f.ID
		o.InputInterface = f.Input
		o.OutputInterface = f.Output
		o.SamplingMode = f.SamplingMode
		o.SamplingInterval = f.SamplingInterval
		o.TimeBasis = "exporter_uptime_and_clock"
		n.EventTime = f.End
		n.Class = "network_flow"
		n.Action = "flow_observed"
		n.Product = "NetFlow v5"
		n.Message = "Exported flow metadata (not packet contents or process identity)"
	} else if r.Raw.Source == "network:suricata" {
		if v.Profile != "suricata" {
			return bad()
		}
		var s struct {
			Timestamp       string      `json:"timestamp"`
			Type            string      `json:"event_type"`
			FlowID          json.Number `json:"flow_id"`
			Source          string      `json:"src_ip"`
			Destination     string      `json:"dest_ip"`
			SourcePort      int         `json:"src_port"`
			DestinationPort int         `json:"dest_port"`
			Protocol        string      `json:"proto"`
			Alert           struct {
				Signature string `json:"signature"`
				ID        uint64 `json:"signature_id"`
				Severity  int    `json:"severity"`
				Action    string `json:"action"`
			} `json:"alert"`
			Flow struct {
				Start           string `json:"start"`
				End             string `json:"end"`
				PacketsToServer uint64 `json:"pkts_toserver"`
				PacketsToClient uint64 `json:"pkts_toclient"`
				BytesToServer   uint64 `json:"bytes_toserver"`
				BytesToClient   uint64 `json:"bytes_toclient"`
			} `json:"flow"`
		}
		if json.Unmarshal([]byte(v.Line), &s) != nil || s.Type == "" || len(s.Type) > 64 {
			return bad()
		}
		at, e := sensorTime(s.Timestamp)
		if e != nil {
			return bad()
		}
		n.EventTime = at
		n.Product = "Suricata"
		n.Network.Kind = "suricata." + s.Type
		n.Network.TimeBasis = "suricata_clock"
		n.Network.FlowID = s.FlowID.String()
		n.Message = "Suricata · " + s.Type
		if s.Source != "" || s.Destination != "" {
			src, e1 := netip.ParseAddr(s.Source)
			dst, e2 := netip.ParseAddr(s.Destination)
			if e1 != nil || e2 != nil || src.Zone() != "" || dst.Zone() != "" || s.SourcePort < 0 || s.SourcePort > 65535 || s.DestinationPort < 0 || s.DestinationPort > 65535 {
				return bad()
			}
			n.SourceIP = src.Unmap().String()
			n.DestinationIP = dst.Unmap().String()
			n.DestinationPort = s.DestinationPort
			n.Network.SourcePort = s.SourcePort
			n.Network.Protocol = map[string]int{"TCP": 6, "UDP": 17, "ICMP": 1, "IPv6-ICMP": 58}[s.Protocol]
			n.Class = "network_flow"
			n.Action = "flow_observed"
		}
		if s.Type == "flow" {
			start, e1 := sensorTime(s.Flow.Start)
			end, e2 := sensorTime(s.Flow.End)
			if e1 != nil || e2 != nil || end.Before(start) || end.After(at.Add(5*time.Second)) {
				return bad()
			}
			n.Network.Start = &start
			n.Network.End = &end
			// Overflow is invalid; counters are never extrapolated for sampling.
			p := s.Flow.PacketsToServer + s.Flow.PacketsToClient
			b := s.Flow.BytesToServer + s.Flow.BytesToClient
			if p < s.Flow.PacketsToServer || b < s.Flow.BytesToServer {
				return bad()
			}
			n.Network.Packets = p
			n.Network.Bytes = b
		}
		if s.Type == "alert" {
			if s.Alert.ID == 0 || s.Alert.Signature == "" || s.Alert.Severity < 1 || s.Alert.Severity > 4 || n.SourceIP == "" {
				return bad()
			}
			n.Class = "network_alert"
			n.Action = "ids_alert"
			n.Code = strconv.FormatUint(s.Alert.ID, 10)
			n.Message = s.Alert.Signature
			n.Network.Signature = s.Alert.Signature
			n.Network.Severity = s.Alert.Severity
		}
	} else if r.Raw.Source == "network:syslog" {
		msg, host, app, at, e := parseSyslog(v.Line, r.Raw.ObservedAt)
		if e != nil {
			return bad()
		}
		n.Message = msg
		n.EventTime = at
		n.Product = "Syslog"
		n.Network.ReportedHost = host
		n.Network.Application = app
		if len(v.Line) > 0 && strings.Contains(v.Line, ">1 ") {
			n.Network.TimeBasis = "syslog_timestamp_or_receive_time"
		}
		if v.Profile == "cef-firewall" || v.Profile == "cef-fess" {
			data, _ := json.Marshal(map[string]string{"line": msg, "profile": strings.TrimPrefix(v.Profile, "cef-")})
			r.Raw.Data = data
			n = normalizeCEF(r, n)
			n.Device = v.Peer + "/" + v.Input + "/" + n.Device
		} else if v.Profile != "syslog" {
			return bad()
		}
	} else {
		return bad()
	}
	if n.EventTime.IsZero() || n.EventTime.After(r.ReceivedAt.Add(5*time.Minute)) {
		return bad()
	}
	return n
}

func sensorTime(s string) (time.Time, error) {
	for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, e := time.Parse(f, s); e == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, ErrInvalid
}

// RFC3164 has no year/timezone. Preserve its timestamp in raw data and use
// receive time rather than guessing. RFC5424 structured data is retained raw.
func parseSyslog(line string, received time.Time) (msg, host, app string, at time.Time, err error) {
	at = received
	if len(line) < 4 || len(line) > 12000 || line[0] != '<' || strings.ContainsAny(line, "\x00\r\n") {
		err = ErrInvalid
		return
	}
	i := strings.IndexByte(line, '>')
	if i < 2 || i > 4 {
		err = ErrInvalid
		return
	}
	pri, e := strconv.Atoi(line[1:i])
	if e != nil || pri < 0 || pri > 191 {
		err = ErrInvalid
		return
	}
	s := line[i+1:]
	if strings.HasPrefix(s, "1 ") {
		p := strings.SplitN(s, " ", 7)
		if len(p) != 7 {
			err = ErrInvalid
			return
		}
		if p[1] != "-" {
			at, e = sensorTime(p[1])
			if e != nil {
				err = e
				return
			}
		}
		host = p[2]
		app = p[3]
		rest := p[6]
		if strings.HasPrefix(rest, "-") {
			if len(rest) > 1 && rest[1] != ' ' {
				err = ErrInvalid
				return
			}
			msg = strings.TrimPrefix(rest[1:], " ")
			return
		}
		if !strings.HasPrefix(rest, "[") {
			err = ErrInvalid
			return
		}
		for strings.HasPrefix(rest, "[") {
			quoted, escaped, closed := false, false, false
			for j := 1; j < len(rest); j++ {
				c := rest[j]
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' && quoted {
					escaped = true
					continue
				}
				if c == '"' {
					quoted = !quoted
				}
				if c == ']' && !quoted {
					rest = rest[j+1:]
					closed = true
					break
				}
			}
			if !closed {
				err = ErrInvalid
				return
			}
		}
		if rest != "" && rest[0] != ' ' {
			err = ErrInvalid
			return
		}
		msg = strings.TrimPrefix(rest, " ")
		return
	}
	if len(s) < 17 {
		err = ErrInvalid
		return
	}
	if _, e = time.Parse("Jan _2 15:04:05", s[:15]); e != nil || s[15] != ' ' {
		err = ErrInvalid
		return
	}
	host, msg, _ = strings.Cut(s[16:], " ")
	if host == "" || msg == "" {
		err = ErrInvalid
	}
	return
}

type NetFlow5 struct {
	Source, Destination, ID                                                              string
	SourcePort, DestinationPort, Protocol, Input, Output, SamplingMode, SamplingInterval int
	Packets, Bytes                                                                       uint64
	Start, End                                                                           time.Time
}

// DecodeNetFlow5 accepts fixed-size v5 only. Unsupported versions/templates are
// rejected explicitly, never interpreted as v5. uint32 subtraction handles wrap.
func DecodeNetFlow5(p []byte) ([]NetFlow5, error) {
	if len(p) < 24 || binary.BigEndian.Uint16(p) != 5 {
		return nil, ErrInvalid
	}
	u16 := func(b []byte) int { return int(binary.BigEndian.Uint16(b)) }
	u32 := binary.BigEndian.Uint32
	count := u16(p[2:])
	if count < 1 || count > 30 || len(p) != 24+48*count || u32(p[12:]) >= 1e9 {
		return nil, ErrInvalid
	}
	exported := time.Unix(int64(u32(p[8:])), int64(u32(p[12:]))).UTC()
	if exported.Year() < 2000 {
		return nil, ErrInvalid
	}
	uptime := u32(p[4:])
	out := make([]NetFlow5, 0, count)
	for i := 0; i < count; i++ {
		r := p[24+48*i : 24+48*(i+1)]
		startAgo, endAgo := uptime-u32(r[24:]), uptime-u32(r[28:])
		if endAgo > startAgo || startAgo > uint32((24*time.Hour)/time.Millisecond) {
			return nil, ErrInvalid
		}
		f := NetFlow5{Source: netip.AddrFrom4([4]byte(r[:4])).String(), Destination: netip.AddrFrom4([4]byte(r[4:8])).String(), SourcePort: u16(r[32:]), DestinationPort: u16(r[34:]), Protocol: int(r[38]), Input: u16(r[12:]), Output: u16(r[14:]), Packets: uint64(u32(r[16:])), Bytes: uint64(u32(r[20:])), Start: exported.Add(-time.Duration(startAgo) * time.Millisecond), End: exported.Add(-time.Duration(endAgo) * time.Millisecond), ID: fmt.Sprintf("%d:%d:%d", p[20], p[21], u32(p[16:])+uint32(i)), SamplingMode: u16(p[22:]) >> 14, SamplingInterval: u16(p[22:]) & 0x3fff}
		out = append(out, f)
	}
	return out, nil
}
