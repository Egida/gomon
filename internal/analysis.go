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

const defaultMaxFlows = 1024

type AnalysisConfiguration struct {
	// orchestration components
	collector  *FlowCollector
	classifier *BehaviorClassifier

	// configuration
	WindowSize time.Duration

	// extra logging options
	showIdle    bool
	savePackets int
	captureDir  string
	linkType    layers.LinkType

	// instance references
	eventFile   *os.File
	logger      *slog.Logger
	eventLogger *EveLogger

	summary         AnalysisSummary
	captureBehavior func(*AnalysisConfiguration, *LocalBehavior) (bool, error)
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

type AnalysisContext struct {
	// instance configuration
	botHost            Host
	c2Host             Host
	sampleID           string        // unique identifier to match behavior to a malware sample
	uninterestingHosts map[Host]bool // List of IP addresses that are not interesting for analysis
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
	savePackets int,
	captureDir string,
	captureBehavior func(*AnalysisConfiguration, *LocalBehavior) (bool, error),
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

	// C2 and other caller-supplied IPs should be excluded from analysis
	filterIPs = append(filterIPs, c2IP)
	uninterestingIPs := map[Host]bool{}
	srcHost, _ := hostFromIPv4String(srcIP)
	c2Host, _ := hostFromIPv4String(c2IP)

	for _, ip := range filterIPs {
		if host, ok := hostFromIPv4String(ip); ok {
			uninterestingIPs[host] = true
		}
	}

	if captureDir == "" {
		captureDir = filepath.Join(".", "captures")
	}
	captureDir = filepath.Clean(captureDir)

	if captureBehavior == nil {
		captureBehavior = defaultCaptureBehavior
	}

	context := AnalysisContext{
		botHost:            srcHost,
		c2Host:             c2Host,
		sampleID:           sampleID,
		uninterestingHosts: uninterestingIPs,
	}
	cfg := classificationConfig{
		packetThreshold:      PacketThreshold,
		destinationThreshold: destinationThreshold,
	}

	return &AnalysisConfiguration{
		logger:          logger,
		eventLogger:     eventLogger,
		eventFile:       file,
		WindowSize:      window,
		showIdle:        showIdle,
		savePackets:     savePackets,
		captureDir:      captureDir,
		captureBehavior: captureBehavior,
		collector:       newFlowCollector(defaultMaxFlows, savePackets, uninterestingIPs, logger),
		classifier:      newBehaviorClassifier(cfg, scanDetectionMode, context, logger),
	}
}

// ProcessBatch processes a (subset) of a window of packets and saves
// intermediate results.
func (config *AnalysisConfiguration) ProcessBatch(
	_ []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	config.collector.ProcessBatch(batch, windowStart)
}

func (config *AnalysisConfiguration) flushResults() {
	stats := config.collector.Flush(config.WindowSize)
	if stats.GlobalPacketCount == 0 && len(stats.FlowCounts) == 0 {
		config.classifier.Reset()
		return
	}
	if stats.Start.IsZero() {
		return
	}

	result := config.classifier.Classify(stats)
	config.emit(result, stats)
}

func (config *AnalysisConfiguration) emit(result ClassificationResult, stats WindowStats) {
	globalBehavior := result.GlobalBehavior

	if config.shouldEmitGlobalBehavior(globalBehavior) {
		config.logGlobalBehavior(globalBehavior)
	}

	capturedFlows := make(map[Flow]bool)
	for _, local := range result.LocalBehaviors {
		localBehavior := local.behavior
		if !config.shouldLogLocalBehavior(globalBehavior, localBehavior) {
			continue
		}
		var captured []gopacket.Packet
		captureKey := local.key

		if capture, err := config.captureBehavior(config, localBehavior); err != nil {
			config.logger.Error("Failed to capture packets", "error", err)
		} else if capture {
			if capturedFlows[captureKey] {
				config.logger.Debug("Skipping duplicate capture for flow")
			} else {
				capturedFlows[captureKey] = true
				captured = stats.PacketSnapshots[captureKey]
			}
		}
		config.logLocalBehavior(localBehavior, captured)
	}
}

func (config *AnalysisConfiguration) logLocalBehavior(
	behavior *LocalBehavior,
	packets []gopacket.Packet,
) {
	if behavior == nil {
		return
	}

	switch behavior.Classification {
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
	case OutboundConnection:
		// outbound events are logged to Eve but don't alter the summary
	default:
		return
	}

	if config.eventLogger == nil {
		return
	}

	if err := config.eventLogger.LogLocalBehavior(behavior); err != nil {
		config.logger.Error("Failed to write eve event", "error", err)
	} else {
		config.logger.Debug(
			"Emitted eve event",
			"classification", behavior.Classification,
			"scope", behavior.Scope,
		)
	}
}

func (config *AnalysisConfiguration) logGlobalBehavior(behavior *GlobalBehavior) {
	if behavior == nil {
		return
	}

	switch behavior.Classification {
	case Idle:
		if !config.showIdle {
			return
		}
		config.summary.IdleEvents++
	case Scan:
		config.summary.ScanEvents++
	default:
		return
	}

	if config.eventLogger == nil {
		return
	}

	if err := config.eventLogger.LogGlobalBehavior(behavior); err != nil {
		config.logger.Error("Failed to write eve event", "error", err)
	} else {
		config.logger.Debug(
			"Emitted eve event",
			"classification", behavior.Classification,
			"scope", behavior.Scope,
		)
	}
}

func (config *AnalysisConfiguration) persistPackets(behavior *LocalBehavior, packets []gopacket.Packet) bool {
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

func (config *AnalysisConfiguration) shouldLogLocalBehavior(globalBehavior *GlobalBehavior, localBehavior *LocalBehavior) bool {
	if localBehavior == nil {
		return false
	}
	if globalBehavior == nil {
		return true
	}
	return !(globalBehavior.Classification == Scan && localBehavior.Classification == OutboundConnection)
}

func (config *AnalysisConfiguration) shouldEmitGlobalBehavior(behavior *GlobalBehavior) bool {
	if behavior == nil {
		return false
	}
	switch behavior.Classification {
	case Scan:
		return true
	case Idle:
		return config.showIdle
	default:
		return false
	}
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

func defaultCaptureBehavior(config *AnalysisConfiguration, behavior *LocalBehavior) (bool, error) {
	if config == nil {
		return false, errors.New("config is nil")
	}
	if behavior == nil {
		return false, nil
	}
	return (behavior.Classification == Attack &&
		behavior.Flow.DstHost != 0 &&
		config.savePackets > 0), nil
}
