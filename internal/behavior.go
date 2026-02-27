package internal

import (
	"fmt"
	"strings"
	"time"
)

type BehaviorScope string

const (
	Global BehaviorScope = "global"
	Local  BehaviorScope = "local"
)

type BehaviorClass string // Classification of the behavior in a particular window

const (
	// local
	Attack             BehaviorClass = "attack"              // any attacking behavior
	OutboundConnection BehaviorClass = "outbound_connection" // normal connectivity behavior

	// global
	Scan BehaviorClass = "scanning" // any scanning behavior
	Idle BehaviorClass = "idle"     // absence of activity
)

// BehaviorFlow identifies packet endpoint details used for local behavior events.
type BehaviorFlow struct {
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstPort    uint16 `json:"port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	SrcHost    Host   `json:"-"`
	DstHost    Host   `json:"-"`
	HasSrcHost bool   `json:"-"`
	HasDstHost bool   `json:"-"`
}

// Equals returns true when two behavior flows represent the same 5-tuple
// (source host/port, destination host/port, protocol).
func (f BehaviorFlow) Equals(other BehaviorFlow) bool {
	if f.HasSrcHost != other.HasSrcHost || f.HasDstHost != other.HasDstHost {
		return false
	}
	if f.HasSrcHost && f.SrcHost != other.SrcHost {
		return false
	}
	if f.HasDstHost && f.DstHost != other.DstHost {
		return false
	}
	return f.SrcPort == other.SrcPort &&
		f.DstPort == other.DstPort &&
		strings.EqualFold(f.Protocol, other.Protocol)
}

// HostEquals returns true when the behavior flows share the same destination host.
func (f BehaviorFlow) HostEquals(other BehaviorFlow) bool {
	if f.HasDstHost && other.HasDstHost {
		return f.DstHost == other.DstHost
	}
	return false
}

// String renders a human-readable endpoint label.
func (f BehaviorFlow) String() string {
	base := ""
	if f.HasDstHost {
		base = f.DstHost.String()
	}
	if f.DstPort > 0 {
		base = fmt.Sprintf("%s:%d", base, f.DstPort)
	}
	if f.Protocol != "" {
		return fmt.Sprintf("%s/%s", base, strings.ToLower(f.Protocol))
	}
	return base
}

type Behavior struct {
	Classification BehaviorClass `json:"classification"`
	Scope          BehaviorScope `json:"scope"`      // Indicates the scope of the behavior (global/local)
	Timestamp      time.Time     `json:"@timestamp"` // @timestamp to comply with Elastic

	PacketRate               float64 `json:"packet_rate"`
	PacketThreshold          float64 `json:"packet_threshold"`
	DestinationRate          float64 `json:"destination_rate"`
	DestinationRateThreshold float64 `json:"destination_rate_threshold"`

	SampleID string  `json:"sample_id"`
	SrcIP    *string `json:"src_ip"`
	SrcPort  *uint16 `json:"src_port,omitempty"`
	C2IP     *string `json:"c2_ip"`

	// Flow IP/s depending on the scope
	DstIPs  *[]string     `json:"dst_ips"`
	DstIP   *string       `json:"dst_ip"`
	DstPort *uint16       `json:"dst_port,omitempty"`
	Proto   string        `json:"proto,omitempty"`
	Flow    *BehaviorFlow `json:"flow,omitempty"`
}

// NewBehavior builds a Behavior with consistent context and flow wiring.
func NewBehavior(
	classification BehaviorClass,
	scope BehaviorScope,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	destinationRate float64,
	destinationRateThreshold float64,
	flow *BehaviorFlow,
	destinationLabels *[]string,
	context *AnalysisContext,
) *Behavior {
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	b := &Behavior{
		Classification:           classification,
		Scope:                    scope,
		Timestamp:                eventTime,
		PacketRate:               packetRate,
		PacketThreshold:          packetThreshold,
		DestinationRate:          destinationRate,
		DestinationRateThreshold: destinationRateThreshold,
	}

	if context != nil {
		if context.sampleID != "" {
			b.SampleID = context.sampleID
		}
		if context.hasSrcHost {
			srcIP := context.srcHost.String()
			b.SrcIP = &srcIP
		}
		if context.hasC2Host {
			c2IP := context.c2Host.String()
			b.C2IP = &c2IP
		}
	}

	if flow != nil {
		destCopy := *flow
		if destCopy.HasSrcHost {
			srcIP := destCopy.SrcHost.String()
			b.SrcIP = &srcIP
		}
		if destCopy.SrcPort > 0 {
			srcPort := destCopy.SrcPort
			b.SrcPort = &srcPort
		}
		if destCopy.HasDstHost {
			dstIP := destCopy.DstHost.String()
			b.DstIP = &dstIP
		}
		if destCopy.DstPort > 0 {
			port := destCopy.DstPort
			b.DstPort = &port
		}
		if destCopy.Protocol != "" {
			b.Proto = destCopy.Protocol
		}
		b.Flow = &destCopy
	}

	if destinationLabels != nil {
		b.DstIPs = destinationLabels
	}

	return b
}
