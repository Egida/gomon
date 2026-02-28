package internal

import (
	"log/slog"
	"time"
)

// classificationConfig holds the thresholds used to classify a flow observation
// into a behavior.
type classificationConfig struct {
	packetThreshold      float64
	destinationThreshold float64
}

// assignBehaviorFlowID looks up or assigns a stable flow ID for b, persisting
// it into current for use by subsequent behaviors in the same window.
func assignBehaviorFlowID(b behavior, current, previous map[behaviorKey]uint64) {
	key := b.key()
	if id, ok := current[key]; ok {
		b.setFlowID(id)
		return
	}
	if id, ok := previous[key]; ok {
		b.setFlowID(id)
		current[key] = id
		return
	}
	id := randomFlowID()
	b.setFlowID(id)
	current[key] = id
}

// localBehaviorResult pairs a classified LocalBehavior with the canonical flow
// key used to look up captured packets.
type localBehaviorResult struct {
	behavior *LocalBehavior
	key      Flow
}

// ClassificationResult holds the output of a single window classification pass.
type ClassificationResult struct {
	LocalBehaviors []localBehaviorResult
	GlobalBehavior *GlobalBehavior
}

// BehaviorClassifier classifies accumulated WindowStats into local and global
// behaviors, maintaining cross-window state for flow-ID continuity and new-host
// tracking.
type BehaviorClassifier struct {
	classificationConfig classificationConfig
	scanDetectionMode    ScanDetectionMode
	previousLocalIDs     map[behaviorKey]uint64
	previousGlobalIDs    map[behaviorKey]uint64
	previousWindowHosts  map[Host]bool
	context              AnalysisContext
	logger               *slog.Logger
}

func newBehaviorClassifier(
	cfg classificationConfig,
	scanDetectionMode ScanDetectionMode,
	context AnalysisContext,
	logger *slog.Logger,
) *BehaviorClassifier {
	return &BehaviorClassifier{
		classificationConfig: cfg,
		scanDetectionMode:    scanDetectionMode,
		context:              context,
		logger:               logger,
		previousLocalIDs:     make(map[behaviorKey]uint64),
		previousGlobalIDs:    make(map[behaviorKey]uint64),
		previousWindowHosts:  make(map[Host]bool),
	}
}

// Reset clears cross-window tracking state. It should be called when an empty
// window is detected so that flow IDs do not carry across gaps.
func (c *BehaviorClassifier) Reset() {
	c.previousLocalIDs = nil
	c.previousGlobalIDs = nil
	c.previousWindowHosts = nil
}

// Classify classifies the given WindowStats into local and global behaviors and
// assigns stable flow IDs.
func (c *BehaviorClassifier) Classify(stats WindowStats) ClassificationResult {
	windowDuration := stats.Duration
	if windowDuration <= 0 {
		c.logger.Warn(
			"Unable to normalize rates due to non-positive duration",
			"window", stats.Duration,
		)
		windowDuration = time.Second
	}
	durationSeconds := windowDuration.Seconds()

	localBehaviors := make([]localBehaviorResult, 0, len(stats.FlowCounts))
	attacked := make(map[Host]bool)

	for flow, flowStats := range stats.FlowCounts {
		localBehavior := c.classifyLocalBehavior(flow, flowStats, stats.Start, durationSeconds)
		localBehaviors = append(localBehaviors, localBehaviorResult{behavior: localBehavior, key: flow})
		if localBehavior.Classification == Attack && localBehavior.Flow.DstHost != 0 {
			attacked[localBehavior.Flow.DstHost] = true
		}
	}

	scanCounts := stats.FlowCounts
	if c.scanDetectionMode == ScanDetectionFilteredHostRate {
		scanCounts = scanCounts.filter(c.context.botHost, func(bf BehaviorFlow) bool {
			return !attacked[bf.DstHost]
		})
	}
	scanHosts := scanCounts.behaviorFlows(c.context.botHost).distinct()
	scanTargets := scanHosts
	if c.scanDetectionMode == ScanDetectionNewHostRate {
		scanTargets = scanHosts.unseen(c.previousWindowHosts)
	}
	c.previousWindowHosts = scanHosts.hostSet()

	c.logger.Debug(
		"Classifying window",
		"windowStart", stats.Start,
		"windowSeconds", durationSeconds,
		"globalPacketCount", stats.GlobalPacketCount,
		"windowFlowCount", len(stats.FlowCounts),
		"scanDetectionMode", c.scanDetectionMode,
		"attackHostCount", len(attacked),
		"scanHostCount", len(scanHosts),
		"scanTargetCount", len(scanTargets),
	)

	globalPacketRate := float64(stats.GlobalPacketCount) / durationSeconds
	scanRate := computeScanRate(durationSeconds, len(scanTargets))
	globalBehavior := c.classifyGlobalBehavior(globalPacketRate, scanRate, scanTargets, stats.Start)

	currentLocalIDs := make(map[behaviorKey]uint64)
	currentGlobalIDs := make(map[behaviorKey]uint64)

	assignBehaviorFlowID(globalBehavior, currentGlobalIDs, c.previousGlobalIDs)
	for i := range localBehaviors {
		assignBehaviorFlowID(localBehaviors[i].behavior, currentLocalIDs, c.previousLocalIDs)
	}

	c.previousLocalIDs = currentLocalIDs
	c.previousGlobalIDs = currentGlobalIDs

	return ClassificationResult{
		LocalBehaviors: localBehaviors,
		GlobalBehavior: globalBehavior,
	}
}

// classifyLocalBehavior constructs a fully-populated LocalBehavior for the
// given canonical flow and its window statistics, handling orientation,
// classification, and directional rate computation in a single step.
func (c *BehaviorClassifier) classifyLocalBehavior(
	flow Flow,
	stats normalizedFlowStats,
	eventTime time.Time,
	durationSeconds float64,
) *LocalBehavior {
	cfg := c.classificationConfig
	botHost := c.context.botHost
	packetRate := float64(stats.TotalPackets()) / durationSeconds

	classification := OutboundConnection
	if c.context.c2Host != 0 && packetRate > cfg.packetThreshold {
		classification = Attack
	}

	canonicalSrc, _ := flow.Hosts()
	behaviorFlow := flow.orientBy(stats, botHost)
	srcToDst, dstToSrc := stats.PacketsAToB, stats.PacketsBToA
	if behaviorFlow.SrcHost != canonicalSrc {
		srcToDst, dstToSrc = stats.PacketsBToA, stats.PacketsAToB
	}

	return &LocalBehavior{
		behaviorBase:    newBehaviorBase(classification, Local, eventTime, packetRate, cfg.packetThreshold, 0, 0, &c.context),
		Flow:            behaviorFlow,
		SrcToDstPackets: srcToDst,
		DstToSrcPackets: dstToSrc,
		SrcToDstRate:    float64(srcToDst) / durationSeconds,
		DstToSrcRate:    float64(dstToSrc) / durationSeconds,
	}
}

// newGlobalBehaviorFromRates constructs a GlobalBehavior classified as Scan
// or Idle based on whether scanRate exceeds the configured threshold.
func (c *BehaviorClassifier) classifyGlobalBehavior(
	globalPacketRate float64,
	scanRate float64,
	scanFlows BehaviorFlows,
	eventTime time.Time,
) *GlobalBehavior {
	cfg := c.classificationConfig

	classification := Idle
	if scanRate > cfg.destinationThreshold {
		classification = Scan
	}
	return NewGlobalBehavior(
		classification, eventTime,
		globalPacketRate, cfg.packetThreshold,
		scanRate, cfg.destinationThreshold,
		scanFlows, &c.context,
	)
}
