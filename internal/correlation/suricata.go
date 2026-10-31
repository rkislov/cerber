// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
)

// Suricata preserves the observer and the original EVE alert. It never treats
// signature severity, an IP or an IDS 'allowed' action as successful exploitation.
func Suricata(n telemetry.Normalized) *telemetry.Detection {
	if n.Status != "parsed" || n.Class != "network_alert" || n.Source != "network:suricata" || n.Network == nil || n.Network.Kind != "suricata.alert" || n.Network.Signature == "" || n.SourceIP == "" || n.DestinationIP == "" {
		return nil
	}
	severity := map[int]string{1: "high", 2: "medium", 3: "low", 4: "low"}[n.Network.Severity]
	if severity == "" {
		return nil
	}
	key := telemetry.ID(n.Network.Input, n.Network.Exporter, n.Network.CaptureInterface, n.Code, n.SourceIP, n.DestinationIP, fmt.Sprint(n.Network.Protocol), fmt.Sprint(n.DestinationPort))
	step := telemetry.ChainStep{EventID: n.ID, AgentID: n.AgentID, AssetID: n.AssetID, At: n.EventTime, Action: n.Action, Code: n.Code, Outcome: n.Outcome, SourceIP: n.SourceIP, DestinationIP: n.DestinationIP, DestinationPort: n.DestinationPort, Network: n.Network, MatchedGroups: []string{}}
	return &telemetry.Detection{ID: telemetry.ID("suricata.alert", "1", n.ID), Rule: "suricata.alert", Version: 1, GroupKey: key, AgentID: n.AgentID, AssetID: n.AssetID, SourceIP: n.SourceIP, ObserverOnly: true, Severity: severity, Title: "Suricata · " + n.Code + " · " + n.Network.Signature, CreatedAt: n.ReceivedAt, FirstSeen: n.EventTime, LastSeen: n.EventTime, Evidence: []string{n.ID}, State: "open", Chain: &telemetry.EventChain{Version: 2, Key: key, Hosts: 1, Steps: []telemetry.ChainStep{step}, Links: []telemetry.ChainLink{}, Limitations: "Сигнатурное наблюдение IDS. Сенсор не является конечным узлом; IP не подтверждает владельца актива или учётную запись. Срабатывание не доказывает успешную эксплуатацию. В режиме SPAN/TAP трафик не блокируется."}}
}
