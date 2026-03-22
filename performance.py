"""
Performance Engineering Module
================================
Real-time performance monitoring and benchmarking:
  • Packets/sec throughput tracking with rolling window
  • Per-packet processing latency measurement
  • Throughput percentiles (p50, p95, p99)
  • Synthetic benchmark mode
"""

from __future__ import annotations

import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PerformanceSnapshot:
    """A single performance measurement snapshot."""
    timestamp: float
    packets_per_sec: float
    bytes_per_sec: float
    avg_latency_us: float
    p50_latency_us: float
    p95_latency_us: float
    p99_latency_us: float
    total_packets: int
    dropped: int


class PerformanceMonitor:
    """Real-time packet processing performance tracker."""

    def __init__(self, window_size: float = 5.0):
        self.window_size = window_size
        # Packet timestamps for throughput
        self._packet_times: deque = deque(maxlen=50000)
        self._byte_counts: deque = deque(maxlen=50000)
        # Latency measurements (microseconds)
        self._latencies: deque = deque(maxlen=10000)
        # Counters
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped = 0
        self._start_time = time.time()

    def record_packet(self, packet_size: int, processing_start: float):
        """Record a processed packet's metrics."""
        now = time.time()
        latency_us = (now - processing_start) * 1_000_000  # microseconds

        self._packet_times.append(now)
        self._byte_counts.append((now, packet_size))
        self._latencies.append(latency_us)
        self.total_packets += 1
        self.total_bytes += packet_size

    def record_drop(self):
        """Record a dropped packet."""
        self.dropped += 1

    @property
    def packets_per_sec(self) -> float:
        """Current packets/sec in the rolling window."""
        if not self._packet_times:
            return 0.0
        now = time.time()
        cutoff = now - self.window_size
        recent = sum(1 for t in self._packet_times if t > cutoff)
        elapsed = min(self.window_size, now - self._start_time)
        return recent / max(elapsed, 0.001)

    @property
    def bytes_per_sec(self) -> float:
        """Current bytes/sec in the rolling window."""
        if not self._byte_counts:
            return 0.0
        now = time.time()
        cutoff = now - self.window_size
        recent_bytes = sum(b for t, b in self._byte_counts if t > cutoff)
        elapsed = min(self.window_size, now - self._start_time)
        return recent_bytes / max(elapsed, 0.001)

    @property
    def latency_stats(self) -> dict:
        """Get latency statistics in microseconds."""
        if not self._latencies:
            return {"avg": 0, "p50": 0, "p95": 0, "p99": 0, "min": 0, "max": 0}
        lats = sorted(self._latencies)
        n = len(lats)
        return {
            "avg": statistics.mean(lats),
            "p50": lats[int(n * 0.50)],
            "p95": lats[int(n * 0.95)] if n > 20 else lats[-1],
            "p99": lats[int(n * 0.99)] if n > 100 else lats[-1],
            "min": lats[0],
            "max": lats[-1],
        }

    def snapshot(self) -> PerformanceSnapshot:
        """Take a current performance snapshot."""
        stats = self.latency_stats
        return PerformanceSnapshot(
            timestamp=time.time(),
            packets_per_sec=self.packets_per_sec,
            bytes_per_sec=self.bytes_per_sec,
            avg_latency_us=stats["avg"],
            p50_latency_us=stats["p50"],
            p95_latency_us=stats["p95"],
            p99_latency_us=stats["p99"],
            total_packets=self.total_packets,
            dropped=self.dropped,
        )

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time

    @property
    def avg_throughput(self) -> float:
        """Overall average packets/sec since start."""
        elapsed = self.uptime
        return self.total_packets / max(elapsed, 0.001)


class PerformanceBenchmark:
    """Synthetic benchmark to measure IDS + dissection throughput."""

    def __init__(self):
        from protocols import IPv4Packet, TCPSegment, TCPFlags
        from ids import IDSEngine
        from analytics import AnalyticsManager
        self.IPv4Packet = IPv4Packet
        self.TCPSegment = TCPSegment
        self.TCPFlags = TCPFlags
        self.IDSEngine = IDSEngine
        self.AnalyticsManager = AnalyticsManager

    def run(self, packet_count: int = 50000) -> dict:
        """Run benchmark with synthetic packets."""
        print("=" * 70)
        print("  PERFORMANCE BENCHMARK")
        print("=" * 70)

        import random

        # Generate synthetic packets
        print(f"\n  Generating {packet_count:,} synthetic packets...")
        packets = []
        for i in range(packet_count):
            ip = self.IPv4Packet(
                version=4, ihl=20, dscp=0, ecn=0, total_length=60 + random.randint(0, 1400),
                identification=i, flags=0x02, fragment_offset=0,
                ttl=64, protocol=6, checksum=0,
                src_ip=f"10.0.{(i//256)%256}.{i%256}",
                dst_ip=f"192.168.{(i//256)%256}.{i%256}",
                options=b"", payload=b"\x00" * 20,
            )
            tcp = self.TCPSegment(
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 53, 8080]),
                seq_num=i, ack_num=0, data_offset=20,
                flags=self.TCPFlags.SYN if i % 10 == 0 else self.TCPFlags.ACK,
                window=65535, checksum=0, urgent_ptr=0,
                options=b"", payload=b"",
            )
            packets.append((ip, tcp))

        # Benchmark 1: IDS only
        print(f"\n  Benchmark 1: IDS Analysis ({packet_count:,} packets)...")
        ids = self.IDSEngine(sensitivity="medium")
        monitor1 = PerformanceMonitor()

        t_start = time.time()
        for ip, tcp in packets:
            pstart = time.time()
            ids.analyze_packet(ip=ip, tcp=tcp)
            monitor1.record_packet(ip.total_length, pstart)
        t_ids = time.time() - t_start

        ids_pps = packet_count / t_ids
        ids_stats = monitor1.latency_stats

        print(f"    Throughput: {ids_pps:,.0f} packets/sec")
        print(f"    Total time: {t_ids*1000:.1f}ms")
        print(f"    Latency: avg={ids_stats['avg']:.1f}us p50={ids_stats['p50']:.1f}us p99={ids_stats['p99']:.1f}us")

        # Benchmark 2: Analytics only
        print(f"\n  Benchmark 2: Analytics Recording ({packet_count:,} packets)...")
        analytics = self.AnalyticsManager()
        monitor2 = PerformanceMonitor()

        t_start = time.time()
        for ip, tcp in packets:
            pstart = time.time()
            analytics.record_packet(
                protocol="TCP", size=ip.total_length,
                src_ip=ip.src_ip, dst_ip=ip.dst_ip,
                src_port=tcp.src_port, dst_port=tcp.dst_port,
                tcp_flags_int=tcp.flags,
            )
            monitor2.record_packet(ip.total_length, pstart)
        t_anal = time.time() - t_start

        anal_pps = packet_count / t_anal
        anal_stats = monitor2.latency_stats

        print(f"    Throughput: {anal_pps:,.0f} packets/sec")
        print(f"    Total time: {t_anal*1000:.1f}ms")
        print(f"    Latency: avg={anal_stats['avg']:.1f}us p50={anal_stats['p50']:.1f}us p99={anal_stats['p99']:.1f}us")

        # Benchmark 3: Combined pipeline
        print(f"\n  Benchmark 3: Full Pipeline = IDS + Analytics ({packet_count:,} packets)...")
        ids2 = self.IDSEngine(sensitivity="medium")
        analytics2 = self.AnalyticsManager()
        monitor3 = PerformanceMonitor()

        t_start = time.time()
        for ip, tcp in packets:
            pstart = time.time()
            ids2.analyze_packet(ip=ip, tcp=tcp)
            analytics2.record_packet(
                protocol="TCP", size=ip.total_length,
                src_ip=ip.src_ip, dst_ip=ip.dst_ip,
                src_port=tcp.src_port, dst_port=tcp.dst_port,
                tcp_flags_int=tcp.flags,
            )
            monitor3.record_packet(ip.total_length, pstart)
        t_combined = time.time() - t_start

        combined_pps = packet_count / t_combined
        combined_stats = monitor3.latency_stats

        print(f"    Throughput: {combined_pps:,.0f} packets/sec")
        print(f"    Total time: {t_combined*1000:.1f}ms")
        print(f"    Latency: avg={combined_stats['avg']:.1f}us p50={combined_stats['p50']:.1f}us p99={combined_stats['p99']:.1f}us")

        # Summary
        print(f"\n{'=' * 70}")
        print(f"  BENCHMARK RESULTS")
        print(f"{'=' * 70}")
        print(f"  {'Component':<25} {'pkt/sec':>12} {'avg lat':>10} {'p99 lat':>10}")
        print(f"  {'─'*25} {'─'*12} {'─'*10} {'─'*10}")
        print(f"  {'IDS Only':<25} {ids_pps:>12,.0f} {ids_stats['avg']:>8.1f}us {ids_stats['p99']:>8.1f}us")
        print(f"  {'Analytics Only':<25} {anal_pps:>12,.0f} {anal_stats['avg']:>8.1f}us {anal_stats['p99']:>8.1f}us")
        print(f"  {'Full Pipeline':<25} {combined_pps:>12,.0f} {combined_stats['avg']:>8.1f}us {combined_stats['p99']:>8.1f}us")
        print(f"  {'─'*25} {'─'*12} {'─'*10} {'─'*10}")

        overhead_pct = ((1/combined_pps - 1/max(ids_pps, anal_pps)) / (1/max(ids_pps, anal_pps))) * 100
        print(f"\n  Pipeline overhead: {overhead_pct:+.1f}%")
        print(f"  Total packets processed: {packet_count * 3:,}")
        print(f"={'=' * 69}")

        return {
            "ids_pps": ids_pps,
            "analytics_pps": anal_pps,
            "combined_pps": combined_pps,
            "ids_latency": ids_stats,
            "analytics_latency": anal_stats,
            "combined_latency": combined_stats,
            "packet_count": packet_count,
        }


def run_benchmark(packet_count: int = 50000) -> dict:
    """Entry point for performance benchmark."""
    bench = PerformanceBenchmark()
    return bench.run(packet_count)


if __name__ == "__main__":
    run_benchmark()
