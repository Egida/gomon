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
	return json.Marshal(h.String())
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

type flowCounts map[Flow]int

func (f flowCounts) topFlowByCount() (BehaviorFlow, int) {
	if len(f) == 0 {
		return BehaviorFlow{}, 0
	}

	var (
		maxFlow  BehaviorFlow
		maxCount int
		maxLabel string
		found    bool
	)

	for flow, count := range f {
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
