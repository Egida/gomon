package internal

import (
	"encoding/binary"
	"strings"

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

func mergeFlowCounts(acc flowCounts, batch flowCounts) flowCounts {
	if len(batch) == 0 {
		return acc
	}

	if acc == nil {
		acc = make(flowCounts, len(batch))
	}

	for key, count := range batch {
		if count == 0 {
			continue
		}
		acc[key] += count
	}

	return acc
}

// countPacketsByFlow tallies packets overall and per flow.
func countPacketsByFlow(
	packets *[]gopacket.Packet,
	exclude map[Host]bool,
	maxFlows int,
) (int, flowCounts, error) {
	if packets == nil || len(*packets) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(flowCounts, maxFlows)
	total := 0

	for _, packet := range *packets {
		if packet == nil {
			continue
		}
		key, ok := flowFromPacket(packet)
		if !ok {
			continue
		}

		behaviorFlow := behaviorFlowFromFlow(key)
		if behaviorFlow.DstHost == 0 {
			continue
		}

		if exclude[behaviorFlow.DstHost] {
			continue
		}

		total++

		if _, exists := hostCounts[key]; exists {
			hostCounts[key]++
			continue
		}

		if len(hostCounts) >= maxFlows {
			return total, hostCounts, &MaxFlowsReached{}
		}

		hostCounts[key] = 1
	}

	return total, hostCounts, nil
}

func behaviorFlowFromFlow(flow Flow) BehaviorFlow {
	var out BehaviorFlow

	src := flow.NetworkFlow.Src()
	dst := flow.NetworkFlow.Dst()

	if srcHost, ok := hostFromEndpoint(src); ok {
		out.SrcHost = srcHost
	}
	if dstHost, ok := hostFromEndpoint(dst); ok {
		out.DstHost = dstHost
	}

	if srcPort, ok := portFromEndpoint(flow.TransportFlow.Src()); ok {
		out.SrcPort = srcPort
	}
	if dstPort, ok := portFromEndpoint(flow.TransportFlow.Dst()); ok {
		out.DstPort = dstPort
	}

	out.Protocol = protocolFromFlow(flow)
	return out
}

func portFromEndpoint(endpoint gopacket.Endpoint) (uint16, bool) {
	raw := endpoint.Raw()
	if len(raw) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(raw), true
}

func protocolFromFlow(flow Flow) string {
	transportType := strings.ToLower(flow.TransportFlow.EndpointType().String())
	switch {
	case strings.Contains(transportType, "tcp"):
		return "tcp"
	case strings.Contains(transportType, "udp"):
		return "udp"
	case strings.Contains(transportType, "sctp"):
		return "sctp"
	}

	networkType := strings.ToLower(flow.NetworkFlow.EndpointType().String())
	if networkType != "" && networkType != "invalidendpoint" {
		return networkType
	}
	return ""
}

func flowsFromCounts(flows flowCounts) []BehaviorFlow {
	if len(flows) == 0 {
		return nil
	}

	list := make([]BehaviorFlow, 0, len(flows))

	for flow := range flows {
		behaviorFlow := behaviorFlowFromFlow(flow)
		if behaviorFlow.DstHost == 0 {
			continue
		}
		list = append(list, behaviorFlow)
	}

	return list
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

func newHosts(current []BehaviorFlow, previous []BehaviorFlow) []BehaviorFlow {
	if len(current) == 0 {
		return nil
	}
	if len(previous) == 0 {
		return current
	}

	seenHosts := make(map[Host]struct{}, len(previous))
	for _, prev := range previous {
		if prev.DstHost != 0 {
			seenHosts[prev.DstHost] = struct{}{}
		}
	}

	var out []BehaviorFlow
	for _, flow := range current {
		if flow.DstHost != 0 {
			if _, exists := seenHosts[flow.DstHost]; exists {
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

func computeScanRate(durationSeconds float64, hostCount int) float64 {
	if durationSeconds <= 0 || hostCount <= 0 {
		return 0
	}

	return float64(hostCount) / durationSeconds
}
