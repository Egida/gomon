package internal

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"
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

// behaviorKey identifies behavior by class and normalized flow hash.
type behaviorKey struct {
	Classification BehaviorClass
	FlowHash       uint64
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

func newBehaviorKeyFromLocalBehavior(behavior *LocalBehavior) behaviorKey {
	if behavior == nil {
		return behaviorKey{}
	}
	return behaviorKey{
		Classification: behavior.Classification,
		FlowHash:       hashBehaviorFlows([]BehaviorFlow{behavior.Flow}),
	}
}

func newBehaviorKeyFromGlobalBehavior(behavior *GlobalBehavior) behaviorKey {
	if behavior == nil {
		return behaviorKey{}
	}
	return behaviorKey{
		Classification: behavior.Classification,
		FlowHash:       hashBehaviorFlows(behavior.Flows),
	}
}

func hashBehaviorFlows(flows []BehaviorFlow) uint64 {
	if len(flows) == 0 {
		return 0
	}

	normalized := make([]BehaviorFlow, len(flows))
	copy(normalized, flows)
	for i := range normalized {
		normalized[i] = canonicalBehaviorFlow(normalized[i])
		normalized[i].Protocol = strings.ToLower(strings.TrimSpace(normalized[i].Protocol))
	}

	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].SrcHost != normalized[j].SrcHost {
			return normalized[i].SrcHost < normalized[j].SrcHost
		}
		if normalized[i].SrcPort != normalized[j].SrcPort {
			return normalized[i].SrcPort < normalized[j].SrcPort
		}
		if normalized[i].DstHost != normalized[j].DstHost {
			return normalized[i].DstHost < normalized[j].DstHost
		}
		if normalized[i].DstPort != normalized[j].DstPort {
			return normalized[i].DstPort < normalized[j].DstPort
		}
		return normalized[i].Protocol < normalized[j].Protocol
	})

	hasher := fnv.New64a()
	for _, flow := range normalized {
		var srcHost [4]byte
		binary.BigEndian.PutUint32(srcHost[:], uint32(flow.SrcHost))
		_, _ = hasher.Write(srcHost[:])

		var srcPort [2]byte
		binary.BigEndian.PutUint16(srcPort[:], flow.SrcPort)
		_, _ = hasher.Write(srcPort[:])

		var dstHost [4]byte
		binary.BigEndian.PutUint32(dstHost[:], uint32(flow.DstHost))
		_, _ = hasher.Write(dstHost[:])

		var dstPort [2]byte
		binary.BigEndian.PutUint16(dstPort[:], flow.DstPort)
		_, _ = hasher.Write(dstPort[:])

		_, _ = hasher.Write([]byte(flow.Protocol))
		_, _ = hasher.Write([]byte{0})
	}

	return hasher.Sum64()
}

func canonicalBehaviorFlow(flow BehaviorFlow) BehaviorFlow {
	if flow.DstHost < flow.SrcHost || (flow.DstHost == flow.SrcHost && flow.DstPort < flow.SrcPort) {
		flow.SrcHost, flow.DstHost = flow.DstHost, flow.SrcHost
		flow.SrcPort, flow.DstPort = flow.DstPort, flow.SrcPort
	}
	return flow
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

	// assignedFlowID is set by analysis batching to preserve continuity across adjacent windows.
	assignedFlowID uint64 `json:"-"`
}

type BehaviorContext struct {
	SampleID string `json:"sample_id,omitempty"`
	BotIP    Host   `json:"bot_ip,omitempty"`
	C2IP     Host   `json:"c2_ip,omitempty"`
}

type LocalBehavior struct {
	behaviorBase
	Flow BehaviorFlow `json:"flow"`

	SrcToDstPackets int     `json:"-"`
	DstToSrcPackets int     `json:"-"`
	SrcToDstRate    float64 `json:"-"`
	DstToSrcRate    float64 `json:"-"`
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
			BotIP:    context.botHost,
			C2IP:     context.c2Host,
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
