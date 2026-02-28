package internal

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"

	"github.com/google/gopacket"
)

type packetRing struct {
	max   int
	items []gopacket.Packet
}

func newPacketRing(max int) *packetRing {
	if max <= 0 {
		max = 1
	}
	return &packetRing{
		max:   max,
		items: make([]gopacket.Packet, 0, max),
	}
}

func (r *packetRing) add(packet gopacket.Packet) {
	if r == nil || r.max <= 0 {
		return
	}
	if len(r.items) < r.max {
		r.items = append(r.items, packet)
		return
	}
	copy(r.items, r.items[1:])
	r.items[len(r.items)-1] = packet
}

func (r *packetRing) snapshot() []gopacket.Packet {
	if r == nil || len(r.items) == 0 {
		return nil
	}
	out := make([]gopacket.Packet, len(r.items))
	copy(out, r.items)
	return out
}

func mergeFlowCounts(acc normalizedFlowCounts, batch normalizedFlowCounts) normalizedFlowCounts {
	if len(batch) == 0 {
		return acc
	}

	if acc == nil {
		acc = make(normalizedFlowCounts, len(batch))
	}

	for key, stats := range batch {
		if stats.TotalPackets() == 0 {
			continue
		}
		current := acc[key]
		current.PacketsAToB += stats.PacketsAToB
		current.PacketsBToA += stats.PacketsBToA
		acc[key] = current
	}

	return acc
}

// countPacketsByFlow tallies packets overall and per normalized bidirectional flow.
// Flows where either endpoint is in exclude are skipped entirely.
func countPacketsByFlow(
	packets *[]gopacket.Packet,
	exclude map[Host]bool,
	maxFlows int,
) (int, normalizedFlowCounts, error) {
	if packets == nil || len(*packets) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(normalizedFlowCounts, maxFlows)
	total := 0

	for _, packet := range *packets {
		if packet == nil {
			continue
		}
		rawFlow, ok := flowFromPacket(packet)
		if !ok {
			continue
		}
		normFlow, srcIsA, ok := rawFlow.canonical()
		if !ok {
			continue
		}
		srcHost, dstHost := normFlow.Hosts()
		if len(exclude) > 0 && (exclude[srcHost] || exclude[dstHost]) {
			continue
		}
		stats, exists := hostCounts[normFlow]
		if !exists && len(hostCounts) >= maxFlows {
			return total, hostCounts, &MaxFlowsReached{}
		}
		if srcIsA {
			stats.PacketsAToB++
		} else {
			stats.PacketsBToA++
		}
		total++
		hostCounts[normFlow] = stats
	}

	if len(hostCounts) == 0 {
		return 0, nil, nil
	}

	return total, hostCounts, nil
}

func isRFC1918(host Host) bool {
	ip := uint32(host)
	// 10.0.0.0/8
	if ip&0xff000000 == 0x0a000000 {
		return true
	}
	// 172.16.0.0/12
	if ip&0xfff00000 == 0xac100000 {
		return true
	}
	// 192.168.0.0/16
	return ip&0xffff0000 == 0xc0a80000
}

// chooseSourceEndpoint returns true if the canonical A side (src) of the flow
// should be treated as the traffic source. The flow must be in canonical form
// (src ≤ dst), so the final tie-break always picks A.
func chooseSourceEndpoint(flow Flow, stats normalizedFlowStats, botHost Host) bool {
	srcHost, dstHost := flow.Hosts()

	aIsBot := botHost != 0 && srcHost == botHost
	bIsBot := botHost != 0 && dstHost == botHost
	if aIsBot && !bIsBot {
		return true
	}
	if bIsBot && !aIsBot {
		return false
	}
	if aIsBot && bIsBot {
		return true // canonical: src ≤ dst
	}

	aIsLocal := isRFC1918(srcHost)
	bIsLocal := isRFC1918(dstHost)
	if aIsLocal && !bIsLocal {
		return true
	}
	if bIsLocal && !aIsLocal {
		return false
	}
	if aIsLocal && bIsLocal {
		return true // canonical: src ≤ dst
	}

	if stats.PacketsAToB < stats.PacketsBToA {
		return true
	}
	if stats.PacketsBToA < stats.PacketsAToB {
		return false
	}

	return true // canonical: src ≤ dst
}

func orientedDirectionStats(
	flow Flow,
	stats normalizedFlowStats,
	botHost Host,
) (srcToDstPackets int, dstToSrcPackets int) {
	if chooseSourceEndpoint(flow, stats, botHost) {
		return stats.PacketsAToB, stats.PacketsBToA
	}
	return stats.PacketsBToA, stats.PacketsAToB
}

func filterNonAttackingFlows(
	destinations normalizedFlowCounts,
	attacked map[Host]bool,
	botHost Host,
) normalizedFlowCounts {
	if len(destinations) == 0 || len(attacked) == 0 {
		return destinations
	}

	filtered := make(normalizedFlowCounts, len(destinations))
	for flow, stats := range destinations {
		behaviorFlow := orientedBehaviorFlow(flow, stats, botHost)
		if !attacked[behaviorFlow.DstHost] {
			filtered[flow] = stats
		}
	}
	return filtered
}

func computeScanRate(durationSeconds float64, hostCount int) float64 {
	if durationSeconds <= 0 || hostCount <= 0 {
		return 0
	}

	return float64(hostCount) / durationSeconds
}

func randomFlowID() uint64 {
	for range 16 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			slog.Error("Failed to read random bytes for flow ID", "error", err)
			continue
		}
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
	panic("randomFlowID: failed to generate non-zero ID after 16 attempts")
}

func uniqueHosts(flows []BehaviorFlow) []BehaviorFlow {
	if len(flows) == 0 {
		return nil
	}

	hosts := make([]BehaviorFlow, 0, len(flows))
	seenHosts := make(map[Host]struct{}, len(flows))
	for _, flow := range flows {
		if flow.DstHost == 0 {
			continue
		}
		if _, exists := seenHosts[flow.DstHost]; exists {
			continue
		}
		seenHosts[flow.DstHost] = struct{}{}
		hosts = append(hosts, flow)
	}

	if len(hosts) == 0 {
		return nil
	}

	return hosts
}

func newHosts(current []BehaviorFlow, previous map[Host]bool) []BehaviorFlow {
	if len(current) == 0 {
		return nil
	}
	if len(previous) == 0 {
		return current
	}

	var out []BehaviorFlow
	for _, flow := range current {
		if flow.DstHost != 0 {
			if previous[flow.DstHost] {
				continue
			}
			out = append(out, flow)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func hostsFromFlows(flows []BehaviorFlow) map[Host]bool {
	out := make(map[Host]bool, len(flows))

	for _, flow := range flows {
		if flow.DstHost != 0 {
			out[flow.DstHost] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func orientedBehaviorFlow(flow Flow, stats normalizedFlowStats, botHost Host) BehaviorFlow {
	srcHost, dstHost := flow.Hosts()
	srcPort, dstPort := flow.Ports()
	if !chooseSourceEndpoint(flow, stats, botHost) {
		srcHost, dstHost = dstHost, srcHost
		srcPort, dstPort = dstPort, srcPort
	}
	return BehaviorFlow{
		SrcHost:  srcHost,
		SrcPort:  srcPort,
		DstHost:  dstHost,
		DstPort:  dstPort,
		Protocol: flow.Protocol(),
	}
}

func flowsFromCounts(flows normalizedFlowCounts, botHost Host) []BehaviorFlow {
	if len(flows) == 0 {
		return nil
	}

	list := make([]BehaviorFlow, 0, len(flows))
	for flow, stats := range flows {
		behaviorFlow := orientedBehaviorFlow(flow, stats, botHost)
		if behaviorFlow.DstHost == 0 {
			continue
		}
		list = append(list, behaviorFlow)
	}
	if len(list) == 0 {
		return nil
	}
	return list
}
