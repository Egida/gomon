package internal

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MaxFlowsReached struct{}

func (e *MaxFlowsReached) Error() string {
	return "maximum number of flows reached"
}

type Host uint32

func (h Host) String() string {
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], uint32(h))
	return netip.AddrFrom4(octets).String()
}

func hostKeyFromIPv4String(ip string) (Host, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return 0, false
	}
	octets := addr.As4()
	return Host(binary.BigEndian.Uint32(octets[:])), true
}

func hostKeyFromEndpoint(endpoint gopacket.Endpoint) (Host, bool) {
	raw := endpoint.Raw()
	if len(raw) != 4 {
		return 0, false
	}
	return Host(binary.BigEndian.Uint32(raw)), true
}

// Flow identifies a packet flow key using gopacket network and transport flows.
type Flow struct {
	NetworkFlow   gopacket.Flow
	TransportFlow gopacket.Flow
}

func (f Flow) Equals(other Flow) bool {
	return f.NetworkFlow == other.NetworkFlow && f.TransportFlow == other.TransportFlow
}

func flowFromPacket(packet gopacket.Packet) (Flow, bool) {
	if packet == nil {
		return Flow{}, false
	}

	network := packet.NetworkLayer()
	if network == nil {
		return Flow{}, false
	}

	key := Flow{
		NetworkFlow: network.NetworkFlow(),
	}

	transport := packet.TransportLayer()
	if transport != nil {
		switch transport.(type) {
		case *layers.TCP, *layers.UDP:
			key.TransportFlow = transport.TransportFlow()
		}
	}

	return key, true
}

type flowCounts map[Flow]int

func topFlowByCount(flows flowCounts) (BehaviorFlow, int) {
	if len(flows) == 0 {
		return BehaviorFlow{}, 0
	}

	var (
		maxFlow  BehaviorFlow
		maxCount int
		maxLabel string
		found    bool
	)

	for flow, count := range flows {
		if count <= 0 {
			continue
		}
		behaviorFlow := behaviorFlowFromFlow(flow)
		label := behaviorFlow.String()
		if !found || count > maxCount || (count == maxCount && label < maxLabel) {
			maxCount = count
			maxFlow = behaviorFlow
			maxLabel = label
			found = true
		}
	}

	if !found {
		return BehaviorFlow{}, 0
	}

	return maxFlow, maxCount
}

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

// countPacketsByFlow tallies packets overall and per flow endpoint.
func countPacketsByFlow(
	pkts *[]gopacket.Packet,
	exclude map[Host]bool,
	maxFlows int,
) (int, flowCounts, error) {
	if pkts == nil || len(*pkts) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(flowCounts, maxFlows)
	total := 0

	for _, packet := range *pkts {
		if packet == nil {
			continue
		}
		key, ok := flowFromPacket(packet)
		if !ok {
			continue
		}

		behaviorFlow := behaviorFlowFromFlow(key)
		if !behaviorFlow.HasDstHost {
			continue
		}

		if behaviorFlow.HasDstHost && exclude[behaviorFlow.DstHost] {
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

	if srcHost, ok := hostKeyFromEndpoint(src); ok {
		out.SrcHost = srcHost
		out.HasSrcHost = true
	}
	if dstHost, ok := hostKeyFromEndpoint(dst); ok {
		out.DstHost = dstHost
		out.HasDstHost = true
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

// getEventTime returns the timestamp of the start of the window, or of the
// first packet in the batch or filtered batch, or the current time if no
// packets are available.
func getEventTime(
	windowStart time.Time,
	batch *[]gopacket.Packet,
) time.Time {
	eventTime := windowStart

	if eventTime.IsZero() {
		if batch != nil && len(*batch) > 0 {
			if md := (*batch)[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		} else {
			eventTime = time.Now()
		}
	}

	return eventTime
}

func flowsFromCounts(flows flowCounts) []BehaviorFlow {
	if len(flows) == 0 {
		return nil
	}

	list := make([]BehaviorFlow, 0, len(flows))

	for flow := range flows {
		behaviorFlow := behaviorFlowFromFlow(flow)
		if !behaviorFlow.HasDstHost {
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
		if !flow.HasDstHost {
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
		if prev.HasDstHost {
			seenHosts[prev.DstHost] = struct{}{}
		}
	}

	var out []BehaviorFlow
	for _, flow := range current {
		if flow.HasDstHost {
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

func hostLabels(hosts []BehaviorFlow) *[]string {
	if len(hosts) == 0 {
		return nil
	}

	labels := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if !host.HasDstHost {
			continue
		}
		labels = append(labels, host.DstHost.String())
	}

	if len(labels) == 0 {
		return nil
	}

	sort.Strings(labels)
	return &labels
}
