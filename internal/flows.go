package internal

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MaxFlowsReached struct{}

func (e *MaxFlowsReached) Error() string {
	return "maximum number of flows reached"
}

// Host contains the IPv4 address of a particular host
type Host uint32

func (h Host) String() string {
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], uint32(h))
	return netip.AddrFrom4(octets).String()
}

func (h Host) MarshalJSON() ([]byte, error) {
	if h == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(h.String())
}

func (h *Host) UnmarshalJSON(data []byte) error {
	if h == nil {
		return nil
	}
	if string(data) == "null" {
		*h = 0
		return nil
	}

	var ip string
	if err := json.Unmarshal(data, &ip); err != nil {
		return err
	}
	host, ok := hostFromIPv4String(ip)
	if !ok {
		*h = 0
		return nil
	}
	*h = host
	return nil
}

func hostFromIPv4String(ip string) (Host, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return 0, false
	}
	octets := addr.As4()
	return Host(binary.BigEndian.Uint32(octets[:])), true
}

func hostFromEndpoint(endpoint gopacket.Endpoint) (Host, bool) {
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

func portFromEndpoint(endpoint gopacket.Endpoint) (uint16, bool) {
	raw := endpoint.Raw()
	if len(raw) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(raw), true
}

// Reverse returns a new Flow with both network and transport directions swapped.
func (f Flow) Reverse() Flow {
	return Flow{
		NetworkFlow:   f.NetworkFlow.Reverse(),
		TransportFlow: f.TransportFlow.Reverse(),
	}
}

// Hosts returns the source and destination IPv4 host addresses of the flow.
func (f Flow) Hosts() (src Host, dst Host) {
	src, _ = hostFromEndpoint(f.NetworkFlow.Src())
	dst, _ = hostFromEndpoint(f.NetworkFlow.Dst())
	return
}

// Ports returns the source and destination ports of the flow's transport layer.
func (f Flow) Ports() (src uint16, dst uint16) {
	src, _ = portFromEndpoint(f.TransportFlow.Src())
	dst, _ = portFromEndpoint(f.TransportFlow.Dst())
	return
}

// Protocol returns the transport protocol of the flow as a lowercase string.
func (f Flow) Protocol() string {
	transportType := strings.ToLower(f.TransportFlow.EndpointType().String())
	switch {
	case strings.Contains(transportType, "tcp"):
		return "tcp"
	case strings.Contains(transportType, "udp"):
		return "udp"
	case strings.Contains(transportType, "sctp"):
		return "sctp"
	}
	networkType := strings.ToLower(f.NetworkFlow.EndpointType().String())
	if networkType != "" && networkType != "invalidendpoint" {
		return networkType
	}
	return ""
}

// canonical returns the flow in canonical form (src ≤ dst by host then port),
// whether the original source direction is preserved (srcIsA=true), and
// whether the flow is valid (both hosts are non-zero).
func (f Flow) canonical() (canonical Flow, srcIsA bool, valid bool) {
	srcHost, _ := hostFromEndpoint(f.NetworkFlow.Src())
	dstHost, _ := hostFromEndpoint(f.NetworkFlow.Dst())
	if srcHost == 0 || dstHost == 0 {
		return Flow{}, false, false
	}
	if srcHost < dstHost {
		return f, true, true
	}
	if srcHost > dstHost {
		return f.Reverse(), false, true
	}
	// Same host: break the tie on port.
	srcPort, _ := portFromEndpoint(f.TransportFlow.Src())
	dstPort, _ := portFromEndpoint(f.TransportFlow.Dst())
	if srcPort <= dstPort {
		return f, true, true
	}
	return f.Reverse(), false, true
}

// orientBy returns a BehaviorFlow oriented so that the traffic source is the
// src endpoint, using chooseSourceEndpoint to determine direction.
func (f Flow) orientBy(stats normalizedFlowStats, botHost Host) BehaviorFlow {
	srcHost, dstHost := f.Hosts()
	srcPort, dstPort := f.Ports()
	if !chooseSourceEndpoint(f, stats, botHost) {
		srcHost, dstHost = dstHost, srcHost
		srcPort, dstPort = dstPort, srcPort
	}
	return BehaviorFlow{
		SrcHost:  srcHost,
		SrcPort:  srcPort,
		DstHost:  dstHost,
		DstPort:  dstPort,
		Protocol: f.Protocol(),
	}
}

type normalizedFlowStats struct {
	PacketsAToB int
	PacketsBToA int
}

func (s normalizedFlowStats) TotalPackets() int {
	return s.PacketsAToB + s.PacketsBToA
}

type normalizedFlowCounts map[Flow]normalizedFlowStats

// behaviorFlows converts each flow in the counts to an oriented BehaviorFlow,
// dropping any with a zero destination host.
func (fc normalizedFlowCounts) behaviorFlows(botHost Host) BehaviorFlows {
	if len(fc) == 0 {
		return nil
	}

	list := make(BehaviorFlows, 0, len(fc))
	for flow, stats := range fc {
		bf := flow.orientBy(stats, botHost)
		if bf.DstHost == 0 {
			continue
		}
		list = append(list, bf)
	}
	if len(list) == 0 {
		return nil
	}
	return list
}

// filter returns a new normalizedFlowCounts containing only flows whose oriented
// BehaviorFlow satisfies keep.
func (fc normalizedFlowCounts) filter(botHost Host, keep func(BehaviorFlow) bool) normalizedFlowCounts {
	if len(fc) == 0 {
		return fc
	}
	filtered := make(normalizedFlowCounts, len(fc))
	for flow, stats := range fc {
		if keep(flow.orientBy(stats, botHost)) {
			filtered[flow] = stats
		}
	}
	return filtered
}
