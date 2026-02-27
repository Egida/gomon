package internal

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"sync"
	"time"
)

const eveTimestampFormat = "2006-01-02T15:04:05.000000Z07:00"

// EveLogger serializes events that mimic Suricata's eve JSON output.
type EveLogger struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

// EveEvent matches the general shape of Suricata eve records.
type EveEvent struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	Host      string         `json:"host,omitempty"`
	SrcIP     string         `json:"src_ip,omitempty"`
	SrcPort   uint16         `json:"src_port,omitempty"`
	DestIP    string         `json:"dest_ip,omitempty"`
	DestPort  uint16         `json:"dest_port,omitempty"`
	Proto     string         `json:"proto,omitempty"`
	FlowID    uint64         `json:"flow_id,omitempty"`
	Alert     *EveAlert      `json:"alert,omitempty"`
	Stats     *EveStats      `json:"stats,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type EveAlert struct {
	Action      string `json:"action,omitempty"`
	GID         int    `json:"gid,omitempty"`
	SignatureID int    `json:"signature_id,omitempty"`
	Rev         int    `json:"rev,omitempty"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type EveStats struct {
	Flow *EveFlowStats `json:"flow,omitempty"`
}

type EveFlowStats struct {
	PacketRate               float64 `json:"packet_rate,omitempty"`
	PacketThreshold          float64 `json:"packet_threshold,omitempty"`
	DestinationRate          float64 `json:"destination_rate,omitempty"`
	DestinationRateThreshold float64 `json:"destination_rate_threshold,omitempty"`
}

// EveDetails keeps gomon specific metadata grouped under a dedicated object.
type EveDetails struct {
	Scope                    BehaviorScope    `json:"scope,omitempty"`
	Context                  *BehaviorContext `json:"context,omitempty"`
	PacketRate               float64          `json:"packet_rate,omitempty"`
	PacketThreshold          float64          `json:"packet_threshold,omitempty"`
	DestinationRate          float64          `json:"destination_rate,omitempty"`
	DestinationRateThreshold float64          `json:"destination_rate_threshold,omitempty"`
}

func NewEveLogger(w io.Writer) *EveLogger {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return &EveLogger{encoder: encoder}
}

func (l *EveLogger) LogLocalBehavior(behavior *LocalBehavior) error {
	if l == nil || behavior == nil {
		return nil
	}
	event := localBehaviorToEveEvent(behavior)
	if event == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.encoder.Encode(event)
}

func (l *EveLogger) LogGlobalBehavior(behavior *GlobalBehavior) error {
	if l == nil || behavior == nil {
		return nil
	}
	event := globalBehaviorToEveEvent(behavior)
	if event == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.encoder.Encode(event)
}

func localBehaviorToEveEvent(behavior *LocalBehavior) *EveEvent {
	base := &behavior.behaviorBase
	event := baseToEvent(base)
	if base.assignedFlowID != 0 {
		event.FlowID = base.assignedFlowID
	} else {
		event.FlowID = flowIDFromLocalBehavior(behavior)
	}
	event.Alert = newEveAlert(base.Classification)
	event.Stats = newEveStats(base)
	event.Metadata = eventMetadataFromLocalBehavior(behavior)

	if behavior.Flow.DstHost != 0 {
		event.DestIP = behavior.Flow.DstHost.String()
	}
	if behavior.Flow.SrcHost != 0 {
		event.SrcIP = behavior.Flow.SrcHost.String()
	}
	if behavior.Flow.SrcPort > 0 {
		event.SrcPort = behavior.Flow.SrcPort
	}
	if behavior.Flow.DstPort > 0 {
		event.DestPort = behavior.Flow.DstPort
	}
	if behavior.Flow.Protocol != "" {
		event.Proto = behavior.Flow.Protocol
	}
	if event.DestIP == "" {
		event.DestIP = "0.0.0.0"
	}
	return event
}

func globalBehaviorToEveEvent(behavior *GlobalBehavior) *EveEvent {
	base := &behavior.behaviorBase
	event := baseToEvent(base)
	if base.assignedFlowID != 0 {
		event.FlowID = base.assignedFlowID
	} else {
		event.FlowID = flowIDFromGlobalBehavior(behavior)
	}
	event.Alert = newEveAlert(base.Classification)
	event.Stats = newEveStats(base)
	event.Metadata = eventMetadataFromGlobalBehavior(behavior)

	switch len(behavior.Flows) {
	case 0:
		event.DestIP = "0.0.0.0"
	case 1:
		if behavior.Flows[0].DstHost != 0 {
			event.DestIP = behavior.Flows[0].DstHost.String()
		} else {
			event.DestIP = "0.0.0.0"
		}
	default:
		event.DestIP = "0.0.0.0"
	}
	return event
}

func baseToEvent(base *behaviorBase) *EveEvent {
	event := &EveEvent{
		EventType: eventTypeFromClass(base.Classification),
	}
	ts := base.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	event.Timestamp = ts.UTC().Format(eveTimestampFormat)
	if base.context != nil && base.context.botHost != 0 {
		event.SrcIP = base.context.botHost.String()
	}
	if base.context != nil && base.context.sampleID != "" {
		event.Host = base.context.sampleID
	}
	return event
}

func eventTypeFromClass(class BehaviorClass) string {
	switch class {
	case Attack, Scan, OutboundConnection:
		return "alert"
	default:
		return "stats"
	}
}

func newEveAlert(class BehaviorClass) *EveAlert {
	switch class {
	case Attack, Scan, OutboundConnection:
	default:
		return nil
	}
	return &EveAlert{
		Action:      "allowed",
		GID:         5,
		SignatureID: signatureIDForBehavior(class),
		Rev:         1,
		Signature:   signatureForBehavior(class),
		Category:    categoryForBehavior(class),
		Severity:    severityForBehavior(class),
	}
}

func newEveStats(base *behaviorBase) *EveStats {
	if base == nil || base.Classification != Idle {
		return nil
	}
	return &EveStats{
		Flow: &EveFlowStats{
			PacketRate:               base.PacketRate,
			PacketThreshold:          base.PacketThreshold,
			DestinationRate:          base.DestinationRate,
			DestinationRateThreshold: base.DestinationRateThreshold,
		},
	}
}

func eventMetadataFromLocalBehavior(behavior *LocalBehavior) map[string]any {
	if behavior == nil {
		return nil
	}
	base := &behavior.behaviorBase
	d := &EveDetails{
		Scope:                    base.Scope,
		Context:                  base.Context,
		PacketRate:               base.PacketRate,
		PacketThreshold:          base.PacketThreshold,
		DestinationRate:          base.DestinationRate,
		DestinationRateThreshold: base.DestinationRateThreshold,
	}
	return map[string]any{"gomon": d}
}

func eventMetadataFromGlobalBehavior(behavior *GlobalBehavior) map[string]any {
	if behavior == nil {
		return nil
	}
	base := &behavior.behaviorBase
	d := &EveDetails{
		Scope:                    base.Scope,
		Context:                  base.Context,
		PacketRate:               base.PacketRate,
		PacketThreshold:          base.PacketThreshold,
		DestinationRate:          base.DestinationRate,
		DestinationRateThreshold: base.DestinationRateThreshold,
	}
	return map[string]any{"gomon": d}
}

func signatureForBehavior(class BehaviorClass) string {
	switch class {
	case Attack:
		return "gomon high packet-rate to single host"
	case Scan:
		return "gomon horizontal scan host-rate exceeded"
	case OutboundConnection:
		return "gomon outbound connection observed"
	default:
		return "gomon event"
	}
}

func categoryForBehavior(class BehaviorClass) string {
	switch class {
	case Attack:
		return "attack"
	case Scan:
		return "scan"
	case OutboundConnection:
		return "connection"
	default:
		return "unsuspicious"
	}
}

func severityForBehavior(class BehaviorClass) int {
	switch class {
	case Attack:
		return 2
	case Scan:
		return 3
	case OutboundConnection:
		return 1
	default:
		return 1
	}
}

func signatureIDForBehavior(class BehaviorClass) int {
	switch class {
	case Attack:
		return 2100001
	case Scan:
		return 2100002
	case OutboundConnection:
		return 2100003
	default:
		return 2100000
	}
}

func flowIDFromLocalBehavior(behavior *LocalBehavior) uint64 {
	hasher := fnv.New64a()
	add := func(value string) {
		if value == "" {
			return
		}
		_, _ = hasher.Write([]byte(value))
	}

	base := &behavior.behaviorBase
	add(string(base.Classification))
	add(string(base.Scope))
	if behavior.Flow.SrcHost != 0 {
		add(behavior.Flow.SrcHost.String())
	}
	if behavior.Flow.SrcPort > 0 {
		add(fmt.Sprintf("%d", behavior.Flow.SrcPort))
	}
	if behavior.Flow.DstHost != 0 {
		add(behavior.Flow.DstHost.String())
	}
	if behavior.Flow.DstPort > 0 {
		add(fmt.Sprintf("%d", behavior.Flow.DstPort))
	}
	add(behavior.Flow.Protocol)
	add(base.Timestamp.UTC().Format(time.RFC3339Nano))
	return hasher.Sum64()
}

func flowIDFromGlobalBehavior(behavior *GlobalBehavior) uint64 {
	hasher := fnv.New64a()
	add := func(value string) {
		if value == "" {
			return
		}
		_, _ = hasher.Write([]byte(value))
	}

	base := &behavior.behaviorBase
	add(string(base.Classification))
	add(string(base.Scope))
	if base.context != nil && base.context.botHost != 0 {
		add(base.context.botHost.String())
	}
	for _, flow := range behavior.Flows {
		if flow.DstHost != 0 {
			add(flow.DstHost.String())
		}
	}
	add(base.Timestamp.UTC().Format(time.RFC3339Nano))
	return hasher.Sum64()
}
