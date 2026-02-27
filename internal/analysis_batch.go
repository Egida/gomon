package internal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// == Analysis

const defaultMaxFlows = 1024

type AnalysisConfiguration struct {
	// configuration
	PacketRateThreshold      float64
	DestinationRateThreshold float64
	WindowSize               time.Duration
	scanDetectionMode        ScanDetectionMode
	maxFlows                 int // maximum number of destinations to analyze per window
	calibrate                bool

	// extra logging options
	showIdle    bool // emit idle windows when requested
	savePackets int  // number of packets to save, 0 means no packets are saved
	captureDir  string
	linkType    layers.LinkType

	// instance references
	eventFile   *os.File
	logger      *slog.Logger
	eventLogger *EveLogger

	result            batchResult
	packetRings       map[Flow]*packetRing
	summary           AnalysisSummary
	captureBehavior   func(*AnalysisConfiguration, *Behavior) (bool, error)
	previousScanHosts []BehaviorFlow

	// static context for logging
	context AnalysisContext

	calibration calibrationStats
}

type AnalysisSummary struct {
	AttackEvents  int
	ScanEvents    int
	IdleEvents    int
	SavedCaptures int
}

func (s AnalysisSummary) TotalAlerts() int {
	return s.AttackEvents + s.ScanEvents
}

type ScanDetectionMode uint8

const (
	ScanDetectionFilteredHostRate ScanDetectionMode = iota
	ScanDetectionHostRate
	ScanDetectionNewHostRate
)

const (
	scanDetectionFilteredHostRateLabel = "filtered-host-rate"
	scanDetectionHostRateLabel         = "host-rate"
	scanDetectionNewHostRateLabel      = "new-host-rate"
)

func (mode ScanDetectionMode) String() string {
	switch mode {
	case ScanDetectionHostRate:
		return scanDetectionHostRateLabel
	case ScanDetectionNewHostRate:
		return scanDetectionNewHostRateLabel
	default:
		return scanDetectionFilteredHostRateLabel
	}
}

func ParseScanDetectionMode(value string) (ScanDetectionMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", scanDetectionFilteredHostRateLabel:
		return ScanDetectionFilteredHostRate, nil
	case scanDetectionHostRateLabel:
		return ScanDetectionHostRate, nil
	case scanDetectionNewHostRateLabel:
		return ScanDetectionNewHostRate, nil
	default:
		return ScanDetectionFilteredHostRate, fmt.Errorf(
			"unsupported scan-detection-mode %q (expected %q, %q, or %q)",
			value,
			scanDetectionHostRateLabel,
			scanDetectionNewHostRateLabel,
			scanDetectionFilteredHostRateLabel,
		)
	}
}

type batchResult struct {
	windowStart       time.Time
	flowPacketCounts  flowCounts
	globalPacketCount int
}

type AnalysisContext struct {
	// instance configuration
	srcHost            Host
	hasSrcHost         bool
	c2Host             Host
	hasC2Host          bool
	sampleID           string        // unique identifier to match behavior to a malware sample
	uninterestingHosts map[Host]bool // List of IP addresses that are not interesting for analysis
}

type calibrationStats struct {
	windows          int
	packetRateSum    float64
	packetRateMax    float64
	hostRateSum      float64
	hostRateMax      float64
	topFlowRateMax   float64
	topFlowCountMax  int
	topFlowCandidate BehaviorFlow
}

func (s *calibrationStats) update(
	packetRate float64,
	hostRate float64,
	topFlow BehaviorFlow,
	topCount int,
	topRate float64,
) {
	if s == nil {
		return
	}
	s.windows++
	s.packetRateSum += packetRate
	if packetRate > s.packetRateMax {
		s.packetRateMax = packetRate
	}
	s.hostRateSum += hostRate
	if hostRate > s.hostRateMax {
		s.hostRateMax = hostRate
	}
	if topRate > s.topFlowRateMax {
		s.topFlowRateMax = topRate
		s.topFlowCountMax = topCount
		s.topFlowCandidate = topFlow
		return
	}
	if topRate == s.topFlowRateMax && topRate > 0 {
		currentLabel := s.topFlowCandidate.String()
		candidateLabel := topFlow.String()
		if currentLabel == "" || candidateLabel < currentLabel {
			s.topFlowCountMax = topCount
			s.topFlowCandidate = topFlow
		}
	}
}

func (s *calibrationStats) packetRateAvg() float64 {
	if s == nil || s.windows == 0 {
		return 0
	}
	return s.packetRateSum / float64(s.windows)
}

func (s *calibrationStats) hostRateAvg() float64 {
	if s == nil || s.windows == 0 {
		return 0
	}
	return s.hostRateSum / float64(s.windows)
}

type CalibrationSummary struct {
	Windows                         int
	PacketRateAvg                   float64
	PacketRateMax                   float64
	HostRateAvg                     float64
	HostRateMax                     float64
	RecommendedPacketThreshold      float64
	RecommendedDestinationThreshold float64
	MaxFlow                         BehaviorFlow
	MaxFlowRate                     float64
	MaxFlowPackets                  int
}

func NewAnalysisConfiguration(
	srcIP string,
	c2IP string,
	filterIPs []string,
	showIdle bool,
	window time.Duration,
	filePath string,
	PacketThreshold float64,
	destinationThreshold float64,
	scanDetectionMode ScanDetectionMode,
	level slog.Level,
	sampleID string,
	calibrate bool,
	savePackets int,
	captureDir string,
	captureBehavior func(*AnalysisConfiguration, *Behavior) (bool, error),
) *AnalysisConfiguration {
	var (
		file        *os.File
		eventWriter io.Writer = os.Stdout
	)

	if filePath != "" {
		var err error
		file, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		eventWriter = file
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	eventLogger := NewEveLogger(eventWriter)

	if window <= 0 {
		panic("window duration must be greater than zero")
	}

	// source and C2 IPs should be excluded from analysis
	filterIPs = append(filterIPs, srcIP, c2IP)
	uninterestingIPs := map[Host]bool{}
	srcHost, hasSrcHost := hostKeyFromIPv4String(srcIP)
	c2Host, hasC2Host := hostKeyFromIPv4String(c2IP)

	for _, ip := range filterIPs {
		if host, ok := hostKeyFromIPv4String(ip); ok {
			uninterestingIPs[host] = true
		}
	}

	var buffers map[Flow]*packetRing
	if savePackets > 0 {
		buffers = make(map[Flow]*packetRing)
	}

	if captureDir == "" {
		captureDir = filepath.Join(".", "captures")
	}
	captureDir = filepath.Clean(captureDir)

	if captureBehavior == nil {
		captureBehavior = defaultCaptureBehavior
	}

	return &AnalysisConfiguration{
		logger:                   logger,
		eventLogger:              eventLogger,
		eventFile:                file,
		PacketRateThreshold:      PacketThreshold,
		DestinationRateThreshold: destinationThreshold,
		WindowSize:               window,
		scanDetectionMode:        scanDetectionMode,
		calibrate:                calibrate,
		showIdle:                 showIdle,
		savePackets:              savePackets,
		captureDir:               captureDir,
		packetRings:              buffers,
		context: AnalysisContext{
			srcHost:            srcHost,
			hasSrcHost:         hasSrcHost,
			c2Host:             c2Host,
			hasC2Host:          hasC2Host,
			sampleID:           sampleID,
			uninterestingHosts: uninterestingIPs,
		},
		captureBehavior: captureBehavior,
		maxFlows:        defaultMaxFlows,
	}
}

// ProcessBatch processes a (subset) of a window of packets and saves
// intermediate results.
func (config *AnalysisConfiguration) ProcessBatch(
	_ []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	if len(batch) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		config.result.windowStart = windowStart
	}

	if config.savePackets > 0 {
		config.captureRecentPackets(batch)
	}

	maxTrackedFlows := config.maxFlows
	if maxTrackedFlows <= 0 {
		maxTrackedFlows = defaultMaxFlows
	}
	globalPacketCount, flowPacketCounts, err := countPacketsByFlow(
		&batch,
		config.context.uninterestingHosts,
		maxTrackedFlows,
	)
	if err != nil {
		var maxErr *MaxFlowsReached
		if errors.As(err, &maxErr) {
			config.logger.Warn(
				"Maximum number of flows reached; continuing with partial counts",
				"limit", maxTrackedFlows,
			)
		} else {
			config.logger.Error("Error counting packet totals", "error", err)
		}
	}

	// Save intermediate results; normalization happens when the window flushes.
	config.result.globalPacketCount += globalPacketCount
	config.result.flowPacketCounts = mergeFlowCounts(
		config.result.flowPacketCounts,
		flowPacketCounts,
	)
}

func (config *AnalysisConfiguration) captureRecentPackets(batch []gopacket.Packet) {
	if config.savePackets <= 0 || len(batch) == 0 || config.packetRings == nil {
		return
	}

	for _, packet := range batch {
		key, ok := flowFromPacket(packet)
		if !ok {
			continue
		}
		config.appendPacketForFlow(key, packet)
	}
}

func (config *AnalysisConfiguration) appendPacketForFlow(key Flow, packet gopacket.Packet) {
	if !config.shouldTrackFlow(key) {
		return
	}

	buf, ok := config.packetRings[key]
	if !ok {
		buf = newPacketRing(config.savePackets)
		config.packetRings[key] = buf
	}
	buf.add(packet)
}

func (config *AnalysisConfiguration) shouldTrackFlow(key Flow) bool {
	if config.savePackets <= 0 {
		return false
	}
	if src, ok := hostKeyFromEndpoint(key.NetworkFlow.Src()); ok && config.context.uninterestingHosts[src] {
		return true
	}
	if dst, ok := hostKeyFromEndpoint(key.NetworkFlow.Dst()); ok && config.context.uninterestingHosts[dst] {
		return true
	}
	return false
}

func (config *AnalysisConfiguration) snapshotFlowPackets(key Flow) []gopacket.Packet {
	if config.packetRings == nil {
		return nil
	}
	buf, ok := config.packetRings[key]
	if !ok || buf == nil {
		return nil
	}
	return buf.snapshot()
}

func (config *AnalysisConfiguration) flushResults() {
	if config.result.globalPacketCount == 0 && len(config.result.flowPacketCounts) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		return
	}
	defer config.resetWindowState()

	windowDuration := config.WindowSize
	if windowDuration <= 0 {
		config.logger.Warn(
			"Unable to normalize rates due to non-positive duration",
			"window", config.WindowSize,
		)
		windowDuration = time.Second
	}
	durationSeconds := windowDuration.Seconds()
	windowEnd := config.result.windowStart.Add(windowDuration)

	if config.calibrate {
		config.logCalibration(windowEnd, durationSeconds)
		return
	}

	type localBehaviorResult struct {
		behavior *Behavior
		key      Flow
	}
	localBehaviors := make([]localBehaviorResult, 0, len(config.result.flowPacketCounts))
	attacked := make(map[Host]bool)

	for key, count := range config.result.flowPacketCounts {
		packetRate := float64(count) / durationSeconds
		behaviorFlow := behaviorFlowFromFlow(key)
		localBehavior := config.classifyLocalBehavior(packetRate, behaviorFlow, config.result.windowStart)
		if localBehavior == nil {
			continue
		}
		localBehaviors = append(localBehaviors, localBehaviorResult{behavior: localBehavior, key: key})
		if localBehavior.Classification == Attack &&
			localBehavior.Flow != nil &&
			localBehavior.Flow.HasDstHost {
			attacked[localBehavior.Flow.DstHost] = true
		}
	}

	scanCounts := config.result.flowPacketCounts
	if config.scanDetectionMode == ScanDetectionFilteredHostRate {
		scanCounts = config.filterNonAttackingFlows(scanCounts, attacked)
	}
	scanDestinations := flowsFromCounts(scanCounts)
	scanHosts := uniqueHosts(scanDestinations)
	scanTargets := scanHosts
	if config.scanDetectionMode == ScanDetectionNewHostRate {
		scanTargets = newHosts(scanHosts, config.previousScanHosts)
	}
	config.previousScanHosts = scanHosts

	config.logger.Debug(
		"Flushing results",
		"windowStart", config.result.windowStart,
		"windowEnd", windowEnd,
		"windowSeconds", durationSeconds,
		"globalPacketCount", config.result.globalPacketCount,
		"flowPacketCounts", config.result.flowPacketCounts,
		"windowFlowCount", len(config.result.flowPacketCounts),
		"scanDetectionMode", config.scanDetectionMode,
		"attackHostCount", len(attacked),
		"scanHostCount", len(scanHosts),
		"scanTargetCount", len(scanTargets),
	)

	// classify global behavior using local attack results
	globalPacketRate := float64(config.result.globalPacketCount) / durationSeconds
	scanRate := computeScanRate(durationSeconds, len(scanTargets))
	scanLabels := hostLabels(scanTargets)

	globalBehavior := config.classifyGlobalBehavior(
		globalPacketRate,
		scanRate,
		scanLabels,
		config.result.windowStart,
	)
	config.logBehavior(globalBehavior, nil)

	// then log local behavior
	capturedFlows := make(map[Flow]struct{})
	for _, local := range localBehaviors {
		localBehavior := local.behavior
		if !config.shouldLogLocalBehavior(globalBehavior, localBehavior) {
			continue
		}
		var captured []gopacket.Packet
		captureKey := local.key

		if capture, err := config.captureBehavior(config, localBehavior); err != nil {
			config.logger.Error("Failed to capture packets", "error", err)
		} else if capture {
			if _, seen := capturedFlows[captureKey]; seen {
				config.logger.Debug("Skipping duplicate capture for flow")
			} else {
				capturedFlows[captureKey] = struct{}{}
				captured = config.snapshotFlowPackets(captureKey)
			}
		}
		config.logBehavior(localBehavior, captured)
	}

}

func (config *AnalysisConfiguration) resetWindowState() {
	config.result = batchResult{}
	if config.savePackets <= 0 {
		config.packetRings = nil
		return
	}
	if config.packetRings == nil {
		config.packetRings = make(map[Flow]*packetRing)
		return
	}
	clear(config.packetRings)
}

func (config *AnalysisConfiguration) logCalibration(windowEnd time.Time, durationSeconds float64) {
	if config == nil {
		return
	}
	if durationSeconds <= 0 {
		durationSeconds = 1
	}

	globalPacketRate := float64(config.result.globalPacketCount) / durationSeconds
	destinations := config.result.flowPacketCounts

	attacked := make(map[Host]bool)

	if config.context.hasC2Host && config.PacketRateThreshold > 0 {
		for key, count := range destinations {
			behaviorFlow := behaviorFlowFromFlow(key)
			if !behaviorFlow.HasDstHost {
				continue
			}
			packetRate := float64(count) / durationSeconds
			if packetRate > config.PacketRateThreshold && behaviorFlow.HasDstHost {
				attacked[behaviorFlow.DstHost] = true
			}
		}
	}

	scanCounts := destinations
	if config.scanDetectionMode == ScanDetectionFilteredHostRate {
		scanCounts = config.filterNonAttackingFlows(scanCounts, attacked)
	}

	scanHosts := uniqueHosts(flowsFromCounts(scanCounts))
	scanTargets := scanHosts
	if config.scanDetectionMode == ScanDetectionNewHostRate {
		scanTargets = newHosts(scanHosts, config.previousScanHosts)
	}
	config.previousScanHosts = scanHosts

	scanRate := computeScanRate(durationSeconds, len(scanTargets))

	topFlow, topCount := topFlowByCount(destinations)
	topRate := 0.0
	if topCount > 0 {
		topRate = float64(topCount) / durationSeconds
	}
	topLabel := "<none>"
	if topCount > 0 {
		topLabel = topFlow.String()
	}

	config.calibration.update(globalPacketRate, scanRate, topFlow, topCount, topRate)

	nullTestActivity := "idle"
	if config.result.globalPacketCount > 0 {
		nullTestActivity = "active"
	}

	args := []any{
		"windowStart", config.result.windowStart,
		"windowEnd", windowEnd,
		"windowSeconds", durationSeconds,
		"packetCount", config.result.globalPacketCount,
		"flowCount", len(destinations),
		"scanTargetCount", len(scanTargets),
		"scanDetectionMode", config.scanDetectionMode.String(),
		"globalPacketRate", globalPacketRate,
		"globalPacketRateAvg", config.calibration.packetRateAvg(),
		"globalPacketRateMax", config.calibration.packetRateMax,
		"hostRate", scanRate,
		"hostRateAvg", config.calibration.hostRateAvg(),
		"hostRateMax", config.calibration.hostRateMax,
		"requiredPacketThreshold", topRate,
		"requiredDestinationThreshold", scanRate,
		"maxFlow", topLabel,
		"maxFlowPackets", topCount,
		"maxFlowRate", topRate,
		"nullTestActivity", nullTestActivity,
	}

	if topCount > 0 {
		args = append(
			args,
			"maxFlowIP", topFlow.DstHost.String(),
			"maxFlowPort", topFlow.DstPort,
			"maxFlowProto", topFlow.Protocol,
		)
	}

	config.logger.Info("Calibration window", args...)
}

func (config *AnalysisConfiguration) logBehavior(
	behavior *Behavior,
	packets []gopacket.Packet,
) {
	if behavior == nil {
		return
	}

	switch behavior.Classification {
	case Idle:
		if !config.showIdle {
			return
		}
		config.summary.IdleEvents++
	case Attack:
		var captured bool
		if config.savePackets > 0 {
			captured = config.persistPackets(behavior, packets)
			if captured {
				config.summary.SavedCaptures++
			}
		}
		config.summary.AttackEvents++
	case Scan:
		config.summary.ScanEvents++
	case OutboundConnection:
		// outbound events are logged to Eve but don't alter the summary
	default:
		return
	}

	if config.eventLogger == nil {
		return
	}

	if err := config.eventLogger.LogBehavior(behavior); err != nil {
		config.logger.Error("Failed to write eve event", "error", err)
	} else {
		config.logger.Debug(
			"Emitted eve event",
			"classification", behavior.Classification,
			"scope", behavior.Scope,
		)
	}
}

func (config *AnalysisConfiguration) persistPackets(behavior *Behavior, packets []gopacket.Packet) bool {
	if config.savePackets <= 0 || behavior == nil {
		return false
	}

	data := packets
	if len(data) == 0 {
		return false
	}

	path, err := WriteBehaviorCapture(config.captureDir, behavior, data, config.linkType)
	if err != nil {
		config.logger.Error(
			"Failed to write captured packets",
			"error", err,
		)
		return false
	}
	if path != "" {
		config.logger.Info(
			"Saved attack packet capture",
			"path", path,
			"count", len(data),
		)
		return true
	}
	return false
}

func (config *AnalysisConfiguration) classifyLocalBehavior(
	packetRate float64,
	flow BehaviorFlow,
	eventTime time.Time,
) *Behavior {
	flowCopy := flow // avoid referencing loop variable

	config.logger.Debug(
		"Classifying local behavior",
		"packetRate", packetRate,
		"threshold", config.PacketRateThreshold,
		"flow", flowCopy.String(),
		"protocol", flowCopy.Protocol,
	)

	// attacks can only occur if a C2 IP is specified (assumed)
	if config != nil && config.context.hasC2Host && packetRate > config.PacketRateThreshold {
		return NewBehavior(
			Attack,
			Local,
			eventTime,
			packetRate,
			config.PacketRateThreshold,
			0,
			0,
			&flowCopy,
			nil,
			&config.context,
		)
	}
	return NewBehavior(
		OutboundConnection,
		Local,
		eventTime,
		packetRate,
		config.PacketRateThreshold,
		0,
		0,
		&flowCopy,
		nil,
		&config.context,
	)
}

func (config *AnalysisConfiguration) shouldLogLocalBehavior(globalBehavior *Behavior, localBehavior *Behavior) bool {
	if localBehavior == nil {
		return false
	}
	if globalBehavior == nil {
		return true
	}
	return !(globalBehavior.Classification == Scan && localBehavior.Classification == OutboundConnection)
}

func (config *AnalysisConfiguration) classifyGlobalBehavior(
	globalPacketRate float64,
	scanRate float64,
	scanLabels *[]string,
	eventTime time.Time,
) *Behavior {
	if globalPacketRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Detected global high packet rate",
			"scope", Global,
			"eventTime", eventTime,
			"packetRate", globalPacketRate,
			"threshold", config.PacketRateThreshold,
		)
	}

	// detected a horizontal scan when the host rate exceeds the configured threshold,
	// regardless of whether the packet-rate condition was satisfied
	if scanRate > config.DestinationRateThreshold {
		config.logger.Debug(
			"Detected horizontal scan host rate",
			"scope", Global,
			"eventTime", eventTime,
			"hostRate", scanRate,
			"scanDetectionMode", config.scanDetectionMode,
			"threshold", config.DestinationRateThreshold,
		)

		return NewBehavior(
			Scan,
			Global,
			eventTime,
			globalPacketRate,
			config.PacketRateThreshold,
			scanRate,
			config.DestinationRateThreshold,
			nil,
			scanLabels,
			&config.context,
		)
	}

	return NewBehavior(
		Idle,
		Global,
		eventTime,
		globalPacketRate,
		config.PacketRateThreshold,
		scanRate,
		config.DestinationRateThreshold,
		nil,
		scanLabels,
		&config.context,
	)
}

func (config *AnalysisConfiguration) filterNonAttackingFlows(
	destinations flowCounts,
	attacked map[Host]bool,
) flowCounts {
	if len(destinations) == 0 || len(attacked) == 0 {
		return destinations
	}

	filtered := make(flowCounts, len(destinations))

	for key, count := range destinations {
		behaviorFlow := behaviorFlowFromFlow(key)
		if !attacked[behaviorFlow.DstHost] {
			filtered[key] = count
		}
	}

	return filtered
}

func (config *AnalysisConfiguration) Close() error {
	if config == nil || config.eventFile == nil {
		return nil
	}
	err := config.eventFile.Close()
	config.eventFile = nil
	return err
}

func (config *AnalysisConfiguration) Summary() AnalysisSummary {
	if config == nil {
		return AnalysisSummary{}
	}
	return config.summary
}

func (config *AnalysisConfiguration) CalibrationSummary() CalibrationSummary {
	if config == nil {
		return CalibrationSummary{}
	}

	stats := config.calibration
	return CalibrationSummary{
		Windows:                         stats.windows,
		PacketRateAvg:                   stats.packetRateAvg(),
		PacketRateMax:                   stats.packetRateMax,
		HostRateAvg:                     stats.hostRateAvg(),
		HostRateMax:                     stats.hostRateMax,
		RecommendedPacketThreshold:      stats.topFlowRateMax,
		RecommendedDestinationThreshold: stats.hostRateMax,
		MaxFlow:                         stats.topFlowCandidate,
		MaxFlowRate:                     stats.topFlowRateMax,
		MaxFlowPackets:                  stats.topFlowCountMax,
	}
}

func defaultCaptureBehavior(config *AnalysisConfiguration, behavior *Behavior) (bool, error) {
	if config == nil {
		return false, errors.New("config is nil")
	}
	if behavior == nil {
		return false, nil
	}
	return (behavior.Classification == Attack &&
		behavior.DstIP != nil &&
		config.savePackets > 0), nil
}
