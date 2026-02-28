package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestEveAttackFormatting(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 10)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attack := findEventByCategory(events, "attack")
	if attack == nil {
		t.Fatalf("expected attack alert, got %v", events)
	}

	if attack.DestIP != "198.51.100.10" {
		t.Fatalf("expected DestIP 198.51.100.10, got %s", attack.DestIP)
	}
	if attack.SrcIP != "10.0.0.5" {
		t.Fatalf("expected SrcIP 10.0.0.5, got %s", attack.SrcIP)
	}
	if attack.SrcPort != 40000 {
		t.Fatalf("expected SrcPort 40000, got %d", attack.SrcPort)
	}
	if attack.DestPort != 8080 {
		t.Fatalf("expected DestPort 8080, got %d", attack.DestPort)
	}
	if attack.Proto != "tcp" {
		t.Fatalf("expected Proto tcp, got %s", attack.Proto)
	}
	if attack.Host != "sample-1" {
		t.Fatalf("expected Host sample-1, got %s", attack.Host)
	}

	gomon := attack.Gomon

	if gomon == nil {
		t.Fatalf("expected gomon to be defined, but got 'nil'")
	}

	if gomon.Context == nil || gomon.Context.C2IP.String() != "203.0.113.50" {
		t.Fatalf("expected gomon.context.c2_ip 203.0.113.50, got %#v", gomon)
	}
	if gomon.PacketThreshold != 1 {
		t.Fatalf("expected packet_threshold 1, got %v", gomon.PacketThreshold)
	}
}

func TestAttackWithSpoofedSourceIPUsesLeastSenderOrientation(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 10)

	spoofedSrc := "192.0.2.250"
	packets := []gopacket.Packet{
		buildTestPacketWithSrc(t, spoofedSrc, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacketWithSrc(t, spoofedSrc, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacketWithSrc(t, spoofedSrc, layers.IPProtocolTCP, "198.51.100.10", 8080),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attack := findEventByCategory(events, "attack")
	if attack == nil {
		t.Fatalf("expected attack alert, got %v", events)
	}

	// No bot/local endpoint is present in flow; least-sender rule picks victim as source.
	if attack.SrcIP != "198.51.100.10" {
		t.Fatalf("expected oriented SrcIP 198.51.100.10, got %s", attack.SrcIP)
	}
	if attack.DestIP != spoofedSrc {
		t.Fatalf("expected oriented DestIP %s, got %s", spoofedSrc, attack.DestIP)
	}
	if attack.Gomon == nil || attack.Gomon.Context == nil {
		t.Fatalf("expected gomon.context.bot_ip to be present, got %#v", attack.Gomon)
	}
	if attack.Gomon.Context.BotIP.String() != "10.0.0.5" {
		t.Fatalf("expected gomon.context.bot_ip 10.0.0.5, got %s", attack.Gomon.Context.BotIP.String())
	}
}

func TestEveScanFormatting(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 3)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.1", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.2", 2323),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.3", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.4", 80),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scan := findEventByCategory(events, "scan")
	if scan == nil {
		t.Fatalf("expected scan alert, got %v", events)
	}

	if scan.DestIP != "0.0.0.0" {
		t.Fatalf("expected DestIP 0.0.0.0 for multi-destination scan, got %s", scan.DestIP)
	}
	if scan.Alert == nil || scan.Alert.Signature == "" {
		t.Fatalf("expected alert signature, got %#v", scan.Alert)
	}

	gomon := scan.Gomon
	if gomon == nil || gomon.Context == nil || gomon.Context.C2IP.String() != "203.0.113.50" {
		t.Fatalf("expected gomon.context.c2_ip 203.0.113.50, got %#v", gomon)
	}
	if gomon.DestinationRate < 3 {
		t.Fatalf("expected destination_rate >= 3, got %v", gomon.DestinationRate)
	}
}

func TestOutboundSuppressedDuringScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.11", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.12", 80),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	scan := findEventByCategory(events, "scan")
	if scan == nil {
		t.Fatalf("expected scan alert, got %v", events)
	}
	if conn := findEventByCategory(events, "connection"); conn != nil {
		t.Fatalf("expected no outbound connection events during scan, got %v", conn)
	}
}

func TestScanEmittedWhenDestinationRateExceedsWithoutPacketRate(t *testing.T) {
	buf := &bytes.Buffer{}
	// Packet threshold is intentionally high so only the destination-rate condition can trigger a scan.
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 100, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.31", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.32", 80),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	if scan := findEventByCategory(events, "scan"); scan == nil {
		t.Fatalf("expected scan alert when destination rate exceeded, got %v", events)
	}
	if conn := findEventByCategory(events, "connection"); conn != nil {
		t.Fatalf("expected no outbound connection events during scan, got %v", conn)
	}
	if attack := findEventByCategory(events, "attack"); attack != nil {
		t.Fatalf("did not expect attack alert when packet rate below threshold, got %#v", attack)
	}
}

func TestOutboundResumesAfterScanWindow(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 100, 2)

	now := time.Now()

	// Window 1: high destination diversity triggers scan, suppressing outbound.
	scanPkts := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.40", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.41", 80),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.42", 443),
	}
	config.ProcessBatch(nil, scanPkts, now)
	config.flushResults()

	// Window 2: normal traffic below thresholds should log outbound connection.
	connPkts := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.40", 22),
	}
	config.ProcessBatch(nil, connPkts, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	if scan := findEventByCategory(events, "scan"); scan == nil {
		t.Fatalf("expected scan alert in first window, got %v", events)
	}
	if conn := findEventByCategory(events, "connection"); conn == nil {
		t.Fatalf("expected outbound connection event in second window, got %v", events)
	}
}

func TestNewHostRateOnlyCountsNewAcrossWindows(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 100, 2)
	config.classifier.scanDetectionMode = ScanDetectionNewHostRate

	now := time.Now()

	windowPkts := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.70", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.71", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.72", 80),
	}
	config.ProcessBatch(nil, windowPkts, now)
	config.flushResults()

	repeatPkts := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.70", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.71", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.72", 80),
	}
	config.ProcessBatch(nil, repeatPkts, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scans := findEventsByCategory(events, "scan")
	if len(scans) != 1 {
		t.Fatalf("expected one scan event for the first window only, got %d (%v)", len(scans), events)
	}
}

func TestAttackDestinationNotLoggedAsOutbound(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 10)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 443),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	attack := findEventByCategory(events, "attack")
	if attack == nil {
		t.Fatalf("expected attack alert, got %v", events)
	}
	connections := findEventsByCategory(events, "connection")
	if len(connections) == 0 {
		t.Fatalf("expected outbound connection event for non-attack destination, got %v", events)
	}
	for _, conn := range connections {
		if conn.DestIP == attack.DestIP && conn.DestPort == attack.DestPort {
			t.Fatalf("attack destination %s:%d also logged as outbound connection: %#v", conn.DestIP, conn.DestPort, conn)
		}
	}
}

func TestSingleDestinationBurstDoesNotTriggerScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 3)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan != nil {
		t.Fatalf("unexpected scan alert for single destination: %#v", scan)
	}
	if attack := findEventByCategory(events, "attack"); attack == nil {
		t.Fatalf("expected attack alert for single destination burst, got %v", events)
	}

}

func TestScanIgnoresAttackDestinations(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 2)
	config.classifier.scanDetectionMode = ScanDetectionFilteredHostRate

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 80),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 80),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan != nil {
		t.Fatalf("unexpected scan alert when only attack traffic exceeds host rate, got %#v", scan)
	}
	if attack := findEventByCategory(events, "attack"); attack == nil {
		t.Fatalf("expected attack alert for high-rate destinations, got %v", events)
	}
}

func TestScanEmittedWithoutC2(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.1", 80),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.2", 81),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.3", 82),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan == nil {
		t.Fatalf("expected scan alert without C2 configured, got %v", events)
	}
	if attack := findEventByCategory(events, "attack"); attack != nil {
		t.Fatalf("did not expect attack alert without C2, got %#v", attack)
	}
}

func TestMultiPortSingleHostDoesNotTriggerScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 24),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan != nil {
		t.Fatalf("unexpected scan alert for multi-port single host, got %v", scan)
	}
	if attack := findEventByCategory(events, "attack"); attack != nil {
		t.Fatalf("did not expect attack alert for multi-port single host, got %#v", attack)
	}
	if conn := findEventByCategory(events, "connection"); conn == nil {
		t.Fatalf("expected outbound connection event for multi-port single host, got %v", events)
	}
}

func TestLocalFlowIDReusedAcrossConsecutiveWindows(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 100)
	now := time.Now()

	first := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
	}
	second := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
	}

	config.ProcessBatch(nil, first, now)
	config.flushResults()
	config.ProcessBatch(nil, second, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attacks := findEventsByCategory(events, "attack")
	if len(attacks) != 2 {
		t.Fatalf("expected 2 attack events, got %d (%v)", len(attacks), events)
	}
	if attacks[0].FlowID == 0 || attacks[1].FlowID == 0 {
		t.Fatalf("expected non-zero flow IDs, got %d and %d", attacks[0].FlowID, attacks[1].FlowID)
	}
	if attacks[0].FlowID != attacks[1].FlowID {
		t.Fatalf("expected matching flow IDs for consecutive identical behavior, got %d and %d", attacks[0].FlowID, attacks[1].FlowID)
	}
}

func TestBidirectionalFlowEmitsSingleLocalAlert(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 100)
	now := time.Now()

	packets := []gopacket.Packet{
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.10", 1111, "198.51.100.20", 2222),
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.10", 1111, "198.51.100.20", 2222),
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.20", 2222, "198.51.100.10", 1111),
	}

	config.ProcessBatch(nil, packets, now)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attacks := findEventsByCategory(events, "attack")
	if len(attacks) != 1 {
		t.Fatalf("expected one local alert for bidirectional pair, got %d (%v)", len(attacks), events)
	}
}

func TestBidirectionalStatsInMetadata(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 100, 100)
	now := time.Now()

	// 10 sends 1 query; 20 sends 2 responses (amplification factor = 2).
	packets := []gopacket.Packet{
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.10", 1111, "198.51.100.20", 2222),
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.20", 2222, "198.51.100.10", 1111),
		buildTestPacketWithTuple(t, layers.IPProtocolUDP, "198.51.100.20", 2222, "198.51.100.10", 1111),
	}

	config.ProcessBatch(nil, packets, now)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	conn := findEventByCategory(events, "connection")
	if conn == nil || conn.Gomon == nil {
		t.Fatalf("expected outbound connection with gomon metadata, got %v", events)
	}
	if conn.Gomon.SrcToDstPackets != 1 || conn.Gomon.DstToSrcPackets != 2 {
		t.Fatalf(
			"expected oriented stats src_to_dst=1,dst_to_src=2 got src_to_dst=%d dst_to_src=%d",
			conn.Gomon.SrcToDstPackets,
			conn.Gomon.DstToSrcPackets,
		)
	}
	if conn.Gomon.AmplificationFactor != 2.0 {
		t.Fatalf("expected amplification_factor 2.0, got %v", conn.Gomon.AmplificationFactor)
	}
	if conn.Gomon.SrcToDstRate <= 0 || conn.Gomon.DstToSrcRate <= 0 {
		t.Fatalf("expected non-zero bidirectional rates, got %#v", conn.Gomon)
	}
}

func TestSourceSelectionPriorityBotThenLocalThenLeast(t *testing.T) {
	t.Run("bot preferred", func(t *testing.T) {
		buf := &bytes.Buffer{}
		config := newTestAnalysisConfigWithC2(buf, "", 100, 100)
		now := time.Now()
		packets := []gopacket.Packet{
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "10.0.0.5", 1111, "198.51.100.20", 2222),
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "198.51.100.20", 2222, "10.0.0.5", 1111),
		}
		config.ProcessBatch(nil, packets, now)
		config.flushResults()
		events := parseEveEvents(t, buf.Bytes())
		conn := findEventByCategory(events, "connection")
		if conn == nil {
			t.Fatalf("expected connection event, got %v", events)
		}
		if conn.SrcIP != "10.0.0.5" {
			t.Fatalf("expected bot as source, got %s", conn.SrcIP)
		}
	})

	t.Run("local preferred", func(t *testing.T) {
		buf := &bytes.Buffer{}
		config := newTestAnalysisConfigWithC2(buf, "", 100, 100)
		now := time.Now()
		packets := []gopacket.Packet{
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "192.168.1.10", 1111, "198.51.100.20", 2222),
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "198.51.100.20", 2222, "192.168.1.10", 1111),
		}
		config.ProcessBatch(nil, packets, now)
		config.flushResults()
		events := parseEveEvents(t, buf.Bytes())
		conn := findEventByCategory(events, "connection")
		if conn == nil {
			t.Fatalf("expected connection event, got %v", events)
		}
		if conn.SrcIP != "192.168.1.10" {
			t.Fatalf("expected RFC1918 endpoint as source, got %s", conn.SrcIP)
		}
	})

	t.Run("least sender then lexical tie", func(t *testing.T) {
		buf := &bytes.Buffer{}
		config := newTestAnalysisConfigWithC2(buf, "", 100, 100)
		now := time.Now()
		packets := []gopacket.Packet{
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "198.51.100.30", 1111, "203.0.113.40", 2222),
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "198.51.100.30", 1111, "203.0.113.40", 2222),
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "203.0.113.40", 2222, "198.51.100.30", 1111),
		}
		config.ProcessBatch(nil, packets, now)
		config.flushResults()
		events := parseEveEvents(t, buf.Bytes())
		conn := findEventByCategory(events, "connection")
		if conn == nil {
			t.Fatalf("expected connection event, got %v", events)
		}
		if conn.SrcIP != "203.0.113.40" {
			t.Fatalf("expected least-sender endpoint as source, got %s", conn.SrcIP)
		}

		buf.Reset()
		packets = []gopacket.Packet{
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "198.51.100.30", 1111, "203.0.113.40", 2222),
			buildTestPacketWithTuple(t, layers.IPProtocolTCP, "203.0.113.40", 2222, "198.51.100.30", 1111),
		}
		config.ProcessBatch(nil, packets, now.Add(time.Second))
		config.flushResults()
		events = parseEveEvents(t, buf.Bytes())
		conn = findEventByCategory(events, "connection")
		if conn == nil {
			t.Fatalf("expected connection event on tie, got %v", events)
		}
		if conn.SrcIP != "198.51.100.30" {
			t.Fatalf("expected lexical source on tie, got %s", conn.SrcIP)
		}
	})
}

func TestLocalFlowIDChangesWhenClassificationChanges(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 2, 100)
	now := time.Now()

	// Window 1: packetRate == threshold, so this remains outbound_connection.
	outbound := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
	}
	// Window 2: packetRate > threshold, same flow now becomes attack.
	attack := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
	}

	config.ProcessBatch(nil, outbound, now)
	config.flushResults()
	config.ProcessBatch(nil, attack, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if len(events) != 2 {
		t.Fatalf("expected 2 local events, got %d (%v)", len(events), events)
	}
	if events[0].Alert == nil || events[0].Alert.Category != "connection" {
		t.Fatalf("expected first event to be connection, got %#v", events[0])
	}
	if events[1].Alert == nil || events[1].Alert.Category != "attack" {
		t.Fatalf("expected second event to be attack, got %#v", events[1])
	}
	if events[0].FlowID == events[1].FlowID {
		t.Fatalf("expected different flow IDs when classification changes, got %d", events[0].FlowID)
	}
}

func TestLocalFlowIDDoesNotCarryAcrossGap(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 100)
	now := time.Now()

	attack := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 8080),
	}

	config.ProcessBatch(nil, attack, now)
	config.flushResults()

	// Gap window: no behavior emitted.
	config.ProcessBatch(nil, []gopacket.Packet{}, now.Add(time.Second))
	config.flushResults()

	config.ProcessBatch(nil, attack, now.Add(2*time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attacks := findEventsByCategory(events, "attack")
	if len(attacks) != 2 {
		t.Fatalf("expected 2 attack events across gap scenario, got %d (%v)", len(attacks), events)
	}
	if attacks[0].FlowID == attacks[1].FlowID {
		t.Fatalf("expected different flow IDs across non-adjacent windows, got %d", attacks[0].FlowID)
	}
}

func TestGlobalFlowIDReusedAcrossConsecutiveEquivalentScans(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 100, 2)
	now := time.Now()

	first := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.40", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.41", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.42", 80),
	}
	second := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.40", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.41", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.42", 80),
	}

	config.ProcessBatch(nil, first, now)
	config.flushResults()
	config.ProcessBatch(nil, second, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scans := findEventsByCategory(events, "scan")
	if len(scans) != 2 {
		t.Fatalf("expected 2 scan events, got %d (%v)", len(scans), events)
	}
	if scans[0].FlowID != scans[1].FlowID {
		t.Fatalf("expected equal flow IDs for equivalent consecutive scans, got %d and %d", scans[0].FlowID, scans[1].FlowID)
	}
}

func TestGlobalFlowIDChangesWhenScanSetChanges(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 100, 2)
	now := time.Now()

	first := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.50", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.51", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.52", 80),
	}
	second := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.50", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.51", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.53", 80),
	}

	config.ProcessBatch(nil, first, now)
	config.flushResults()
	config.ProcessBatch(nil, second, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scans := findEventsByCategory(events, "scan")
	if len(scans) != 2 {
		t.Fatalf("expected 2 scan events, got %d (%v)", len(scans), events)
	}
	if scans[0].FlowID == scans[1].FlowID {
		t.Fatalf("expected different flow IDs when scan set changes, got %d", scans[0].FlowID)
	}
}

func TestGlobalFlowIDDeterministicAgainstFlowOrder(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 100, 2)
	now := time.Now()

	first := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.60", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.61", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.62", 80),
	}
	second := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.62", 80),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.60", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.61", 23),
	}

	config.ProcessBatch(nil, first, now)
	config.flushResults()
	config.ProcessBatch(nil, second, now.Add(time.Second))
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scans := findEventsByCategory(events, "scan")
	if len(scans) != 2 {
		t.Fatalf("expected 2 scan events, got %d (%v)", len(scans), events)
	}
	if scans[0].FlowID != scans[1].FlowID {
		t.Fatalf("expected order-independent scan flow IDs, got %d and %d", scans[0].FlowID, scans[1].FlowID)
	}
}

func TestCountPacketsByFlowExcludesUninterestingDestinations(t *testing.T) {
	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.201", 22),
	}

	exclude := map[Host]bool{}
	excludedHost, ok := hostFromIPv4String("198.51.100.200")
	if !ok {
		t.Fatalf("failed to parse excluded host")
	}
	exclude[excludedHost] = true

	total, counts, err := countPacketsByFlow(&packets, exclude, defaultMaxFlows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected tracked packet total 1, got %d", total)
	}
	if len(counts) != 1 {
		t.Fatalf("expected one tracked flow, got %d", len(counts))
	}

	for flow, stats := range counts {
		behaviorFlow := orientedBehaviorFlow(flow, stats, 0)
		if behaviorFlow.DstHost == excludedHost {
			t.Fatalf("excluded destination %s was tracked in flow counts", excludedHost.String())
		}
	}
}

func newTestAnalysisConfigWithC2(w io.Writer, c2 string, packetThresh, destinationThresh float64) *AnalysisConfiguration {
	config := NewAnalysisConfiguration(
		"10.0.0.5",
		c2,
		nil,
		false,
		time.Second,
		"",
		packetThresh,
		destinationThresh,
		ScanDetectionFilteredHostRate,
		slog.LevelError,
		"sample-1",
		0,
		"",
		nil,
	)

	if w != nil {
		config.eventLogger = NewEveLogger(w)
	}
	config.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	return config
}

type parsedEveEvent struct {
	EveEvent
	Gomon *EveDetails
}

func parseEveEvents(t *testing.T, data []byte) []parsedEveEvent {
	t.Helper()

	var events []parsedEveEvent
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev parsedEveEvent
		if err := json.Unmarshal(line, &ev.EveEvent); err != nil {
			t.Fatalf("failed to unmarshal eve event: %v (line: %s)", err, line)
		}
		if ev.Metadata != nil {
			if gomonRaw, ok := ev.Metadata["gomon"]; ok {
				rawJSON, err := json.Marshal(gomonRaw)
				if err != nil {
					t.Fatalf("failed to marshal gomon metadata: %v", err)
				}
				var gm EveDetails
				if err := json.Unmarshal(rawJSON, &gm); err != nil {
					t.Fatalf("failed to unmarshal gomon metadata: %v", err)
				}
				ev.Gomon = &gm
			}
		}
		events = append(events, ev)
	}

	return events
}

func findEventByCategory(events []parsedEveEvent, category string) *parsedEveEvent {
	for i := range events {
		if events[i].Alert != nil && events[i].Alert.Category == category {
			return &events[i]
		}
	}
	return nil
}

func findEventsByCategory(events []parsedEveEvent, category string) []parsedEveEvent {
	var matches []parsedEveEvent
	for _, ev := range events {
		if ev.Alert != nil && ev.Alert.Category == category {
			matches = append(matches, ev)
		}
	}
	return matches
}

func buildTestPacket(t *testing.T, proto layers.IPProtocol, dstIP string, dstPort uint16) gopacket.Packet {
	t.Helper()
	return buildTestPacketWithSrc(t, "10.0.0.5", proto, dstIP, dstPort)
}

func buildTestPacketWithSrc(
	t *testing.T,
	srcIP string,
	proto layers.IPProtocol,
	dstIP string,
	dstPort uint16,
) gopacket.Packet {
	return buildTestPacketWithTuple(t, proto, srcIP, 40000, dstIP, dstPort)
}

func buildTestPacketWithTuple(
	t *testing.T,
	proto layers.IPProtocol,
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
) gopacket.Packet {
	t.Helper()

	src := net.ParseIP(srcIP)
	if src == nil {
		t.Fatalf("invalid src ip %q", srcIP)
	}
	src = src.To4()
	if src == nil {
		t.Fatalf("src ip must be IPv4, got %q", srcIP)
	}
	dst := net.ParseIP(dstIP)
	if dst == nil {
		t.Fatalf("invalid dst ip %q", dstIP)
	}
	dst = dst.To4()
	if dst == nil {
		t.Fatalf("dst ip must be IPv4, got %q", dstIP)
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    src,
		DstIP:    dst,
		Protocol: proto,
	}

	var transport gopacket.SerializableLayer
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(&ip)
		transport = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(&ip)
		transport = udp
	default:
		t.Fatalf("unsupported proto: %v", proto)
	}

	payload := gopacket.Payload([]byte{0x01, 0x02, 0x03, 0x04})
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	if err := gopacket.SerializeLayers(buffer, opts, &eth, &ip, transport, payload); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = ci

	return packet
}
