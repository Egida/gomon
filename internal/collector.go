package internal

import (
	"errors"
	"log/slog"
	"time"

	"github.com/google/gopacket"
)

// batchResult accumulates per-window packet statistics before they are flushed.
type batchResult struct {
	windowStart       time.Time
	flowPacketCounts  normalizedFlowCounts
	globalPacketCount int
}

// WindowStats holds the accumulated per-window packet statistics produced by
// FlowCollector.Flush.
type WindowStats struct {
	Start             time.Time
	Duration          time.Duration
	GlobalPacketCount int
	FlowCounts        normalizedFlowCounts
	PacketSnapshots   map[Flow][]gopacket.Packet
}

// FlowCollector accumulates packet statistics and optional packet captures over
// a single analysis window.
type FlowCollector struct {
	result             batchResult
	packetRings        map[Flow]*packetRing
	maxFlows           int
	savePackets        int
	uninterestingHosts map[Host]bool
	logger             *slog.Logger
}

func newFlowCollector(
	maxFlows int,
	savePackets int,
	uninterestingHosts map[Host]bool,
	logger *slog.Logger,
) *FlowCollector {
	var buffers map[Flow]*packetRing
	if savePackets > 0 {
		buffers = make(map[Flow]*packetRing)
	}
	if maxFlows <= 0 {
		maxFlows = defaultMaxFlows
	}
	return &FlowCollector{
		maxFlows:           maxFlows,
		savePackets:        savePackets,
		uninterestingHosts: uninterestingHosts,
		packetRings:        buffers,
		logger:             logger,
	}
}

// ProcessBatch processes a batch of packets from a window starting at windowStart.
func (c *FlowCollector) ProcessBatch(batch []gopacket.Packet, windowStart time.Time) {
	if len(batch) == 0 {
		return
	}
	if c.result.windowStart.IsZero() {
		c.result.windowStart = windowStart
	}

	if c.savePackets > 0 {
		c.captureRecentPackets(batch)
	}

	globalPacketCount, flowPacketCounts, err := countPacketsByFlow(
		&batch,
		c.uninterestingHosts,
		c.maxFlows,
	)
	if err != nil {
		var maxErr *MaxFlowsReached
		if errors.As(err, &maxErr) {
			c.logger.Warn(
				"Maximum number of flows reached; continuing with partial counts",
				"limit", c.maxFlows,
			)
		} else {
			c.logger.Error("Error counting packet totals", "error", err)
		}
	}

	c.result.globalPacketCount += globalPacketCount
	c.result.flowPacketCounts = mergeFlowCounts(
		c.result.flowPacketCounts,
		flowPacketCounts,
	)
}

// Flush returns the accumulated WindowStats and resets internal state.
func (c *FlowCollector) Flush(windowSize time.Duration) WindowStats {
	defer c.resetWindowState()

	stats := WindowStats{
		Start:             c.result.windowStart,
		Duration:          windowSize,
		GlobalPacketCount: c.result.globalPacketCount,
		FlowCounts:        c.result.flowPacketCounts,
	}

	if len(c.packetRings) > 0 {
		snapshots := make(map[Flow][]gopacket.Packet, len(c.packetRings))
		for flow, ring := range c.packetRings {
			if snap := ring.snapshot(); len(snap) > 0 {
				snapshots[flow] = snap
			}
		}
		if len(snapshots) > 0 {
			stats.PacketSnapshots = snapshots
		}
	}

	return stats
}

func (c *FlowCollector) captureRecentPackets(batch []gopacket.Packet) {
	if c.savePackets <= 0 || len(batch) == 0 || c.packetRings == nil {
		return
	}
	for _, packet := range batch {
		rawFlow, ok := flowFromPacket(packet)
		if !ok {
			continue
		}
		canonical, _, ok := rawFlow.canonical()
		if !ok {
			continue
		}
		c.appendPacketForFlow(canonical, packet)
	}
}

func (c *FlowCollector) appendPacketForFlow(flow Flow, packet gopacket.Packet) {
	if !c.shouldTrackFlow(flow) {
		return
	}
	buf, ok := c.packetRings[flow]
	if !ok {
		buf = newPacketRing(c.savePackets)
		c.packetRings[flow] = buf
	}
	buf.add(packet)
}

func (c *FlowCollector) shouldTrackFlow(flow Flow) bool {
	if c.savePackets <= 0 {
		return false
	}
	srcHost, dstHost := flow.Hosts()
	return !c.uninterestingHosts[srcHost] && !c.uninterestingHosts[dstHost]
}

func (c *FlowCollector) resetWindowState() {
	c.result = batchResult{}
	if c.savePackets <= 0 {
		c.packetRings = nil
		return
	}
	if c.packetRings == nil {
		c.packetRings = make(map[Flow]*packetRing)
		return
	}
	clear(c.packetRings)
}
