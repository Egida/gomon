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
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	SrcHost  Host   `json:"src_host,omitempty"`
	DstHost  Host   `json:"dst_host,omitempty"`
}

// Equals returns true when two behavior flows represent the same 5-tuple
// (source host/port, destination host/port, protocol).
func (f BehaviorFlow) Equals(other BehaviorFlow) bool {
	if f.SrcHost != other.SrcHost {
		return false
	}
	if f.DstHost != other.DstHost {
		return false
	}
	return f.SrcPort == other.SrcPort &&
		f.DstPort == other.DstPort &&
		strings.EqualFold(f.Protocol, other.Protocol)
}

// HostEquals returns true when the behavior flows share the same destination host.
func (f BehaviorFlow) HostEquals(other BehaviorFlow) bool {
	if f.DstHost != 0 && other.DstHost != 0 {
		return f.DstHost == other.DstHost
	}
	return false
}

// String renders a human-readable endpoint label.
func (f BehaviorFlow) String() string {
	base := ""
	if f.DstHost != 0 {
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

type behaviorBase struct {
	Classification BehaviorClass `json:"classification"`
	Scope          BehaviorScope `json:"scope"`      // Indicates the scope of the behavior (global/local)
	Timestamp      time.Time     `json:"@timestamp"` // @timestamp to comply with Elastic

	PacketRate               float64 `json:"packet_rate"`
	PacketThreshold          float64 `json:"packet_threshold"`
	DestinationRate          float64 `json:"destination_rate"`
	DestinationRateThreshold float64 `json:"destination_rate_threshold"`

	Context *BehaviorContext `json:"context,omitempty"`
	context *AnalysisContext `json:"-"`
}

type BehaviorContext struct {
	SampleID string  `json:"sample_id,omitempty"`
	SrcIP    *string `json:"src_ip,omitempty"`
	C2IP     *string `json:"c2_ip,omitempty"`
}

type LocalBehavior struct {
	behaviorBase
	Flow BehaviorFlow `json:"flow"`
}

type GlobalBehavior struct {
	behaviorBase
	Flows []BehaviorFlow `json:"flows,omitempty"`
}

func newBehaviorBase(
	classification BehaviorClass,
	scope BehaviorScope,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	destinationRate float64,
	destinationRateThreshold float64,
	context *AnalysisContext,
) behaviorBase {
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	base := behaviorBase{
		Classification:           classification,
		Scope:                    scope,
		Timestamp:                eventTime,
		PacketRate:               packetRate,
		PacketThreshold:          packetThreshold,
		DestinationRate:          destinationRate,
		DestinationRateThreshold: destinationRateThreshold,
		context:                  context,
	}

	if context != nil {
		ctx := &BehaviorContext{
			SampleID: context.sampleID,
		}
		if context.srcHost != 0 {
			src := context.srcHost.String()
			ctx.SrcIP = &src
		}
		if context.hasC2Host {
			c2 := context.c2Host.String()
			ctx.C2IP = &c2
		}
		base.Context = ctx
	}

	return base
}

func NewLocalBehavior(
	classification BehaviorClass,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	flow BehaviorFlow,
	context *AnalysisContext,
) *LocalBehavior {
	base := newBehaviorBase(
		classification,
		Local,
		eventTime,
		packetRate,
		packetThreshold,
		0,
		0,
		context,
	)

	flowCopy := flow
	return &LocalBehavior{
		behaviorBase: base,
		Flow:         flowCopy,
	}
}

func NewGlobalBehavior(
	classification BehaviorClass,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	destinationRate float64,
	destinationRateThreshold float64,
	flows []BehaviorFlow,
	context *AnalysisContext,
) *GlobalBehavior {
	base := newBehaviorBase(
		classification,
		Global,
		eventTime,
		packetRate,
		packetThreshold,
		destinationRate,
		destinationRateThreshold,
		context,
	)

	if len(flows) == 0 {
		return &GlobalBehavior{behaviorBase: base}
	}

	out := make([]BehaviorFlow, len(flows))
	copy(out, flows)
	return &GlobalBehavior{
		behaviorBase: base,
		Flows:        out,
	}
}
