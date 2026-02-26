package internal

import "time"

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
	C2IP     *string `json:"c2_ip"`

	// Destination IP/s depending on the scope
	DstIPs      *[]string    `json:"dst_ips"`
	DstIP       *string      `json:"dst_ip"`
	DstPort     *uint16      `json:"dst_port,omitempty"`
	Proto       string       `json:"proto,omitempty"`
	Destination *Destination `json:"destination,omitempty"`
}

// NewBehavior builds a Behavior with consistent context and destination wiring.
func NewBehavior(
	classification BehaviorClass,
	scope BehaviorScope,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	destinationRate float64,
	destinationRateThreshold float64,
	destination *Destination,
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
		if context.srcIP != "" {
			b.SrcIP = &context.srcIP
		}
		if context.c2IP != "" {
			b.C2IP = &context.c2IP
		}
	}

	if destination != nil {
		destCopy := *destination
		if destCopy.IP != "" {
			dstIP := destCopy.IP
			b.DstIP = &dstIP
		}
		if destCopy.Port > 0 {
			port := destCopy.Port
			b.DstPort = &port
		}
		if destCopy.Protocol != "" {
			b.Proto = destCopy.Protocol
		}
		b.Destination = &destCopy
	}

	if destinationLabels != nil {
		b.DstIPs = destinationLabels
	}

	return b
}
