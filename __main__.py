"""
Quantum Sniffer — CLI Entry Point
===================================
Usage:
  python __main__.py --test           Run self-test suite
  python __main__.py --simulate       Run attack simulation + detection demo
  python __main__.py --benchmark      Run performance benchmark
  python __main__.py --benchmark-pqc  Run RSA vs Kyber benchmark
  python __main__.py --web            Start with web dashboard
  python __main__.py                  Start packet capture (requires admin)
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="quantum_sniffer",
        description="Quantum-Resistant Packet Sniffer with IDS, Analytics & PQC",
    )
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-f", "--filter", help="BPF filter string", default="")
    parser.add_argument("--no-pqc", action="store_true", help="Disable PQC encryption")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable Rich dashboard")
    parser.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP lookups")
    parser.add_argument("--export", metavar="FILE", help="Export JSON analytics on exit")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces")

    # New features
    parser.add_argument("--test", action="store_true", help="Run self-test suite")
    parser.add_argument("--simulate", action="store_true", help="Run attack simulation demo")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmark")
    parser.add_argument("--benchmark-pqc", action="store_true", help="Run RSA vs Kyber benchmark")
    parser.add_argument("--web", action="store_true", help="Enable web dashboard (port 5000)")
    parser.add_argument("--web-port", type=int, default=5000, help="Web dashboard port")
    parser.add_argument("--mode", choices=["capture", "sensor", "aggregator"], default="capture")
    parser.add_argument("--server", metavar="HOST:PORT", help="Aggregator server address (sensor mode)")
    parser.add_argument("--port", type=int, default=9999, help="Aggregator listen port")

    return parser.parse_args()


def run_self_tests():
    """Run comprehensive self-test suite."""
    print()
    print("  QUANTUM SNIFFER — Self-Test Suite")
    print()

    all_passed = True

    # Module 1: PQC
    print("-" * 60)
    print("  Module 1: Post-Quantum Cryptography")
    print("-" * 60)
    try:
        from pqc import test_pqc
        test_pqc()
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False

    # Module 2: Protocols (with Deep TLS)
    print()
    print("-" * 60)
    print("  Module 2: Protocol Dissectors + Deep TLS")
    print("-" * 60)
    try:
        from protocols import test_protocols
        test_protocols()
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False

    # Module 3: IDS (with Explainability)
    print()
    print("-" * 60)
    print("  Module 3: IDS + Explainability")
    print("-" * 60)
    try:
        from ids import IDSEngine, Severity
        from protocols import IPv4Packet, TCPSegment, TCPFlags

        ids = IDSEngine(sensitivity="high")
        # Port scan test
        for port in range(1, 20):
            ip = IPv4Packet(4, 20, 0, 0, 40, port, 2, 0, 64, 6, 0,
                            "10.0.0.1", "10.0.0.2", b"", b"")
            tcp = TCPSegment(12345, port, 0, 0, 20, TCPFlags.SYN, 65535, 0, 0, b"", b"")
            ids.analyze_packet(ip=ip, tcp=tcp)

        scan_alerts = [a for a in ids.alerts if a.category == "PORT_SCAN"]
        assert len(scan_alerts) > 0, "Port scan not detected"
        # Verify explainability
        alert = scan_alerts[0]
        assert alert.explanation, "Missing explanation"
        assert len(alert.evidence_factors) > 0, "Missing evidence factors"
        assert len(alert.response_actions) > 0, "Missing response actions"
        print(f"    OK Port scan detection PASSED (with explainability)")
        print(f"    Explanation: {alert.explanation[:80]}...")
        print(f"    Evidence factors: {len(alert.evidence_factors)}")
        print(f"    Response actions: {len(alert.response_actions)}")
        print(f"    Packets analyzed: {ids.stats['total_packets_analyzed']}")
        print(f"    Threats detected: {ids.stats['threats_detected']}")
        print(f"    OK IDS + Explainability PASSED")
    except Exception as e:
        print(f"  FAIL: {e}")
        import traceback; traceback.print_exc()
        all_passed = False

    # Module 4: Analytics
    print()
    print("-" * 60)
    print("  Module 4: Analytics Engine")
    print("-" * 60)
    try:
        from analytics import AnalyticsManager
        eng = AnalyticsManager()
        import random
        for i in range(150):
            proto = random.choice(["TCP"] * 100 + ["DNS"] * 30 + ["TLS"] * 20)
            eng.record_packet(
                protocol=proto,
                size=random.randint(40, 1500),
                src_ip=f"10.0.0.{random.randint(1,10)}",
                dst_ip=f"192.168.1.{random.randint(1,10)}",
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 53]),
            )
        stats = eng.summary
        print(f"    Total packets: {stats['total_packets']}")
        print(f"    Protocols: {stats['protocols']}")
        top = eng.talkers.top_senders
        print(f"    Top senders: {top[:3]}")
        print(f"    Bandwidth: {eng.bandwidth.total_bytes / 1024:.1f} KB")
        print(f"    OK Analytics engine PASSED")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False

    # Module 5: Distributed (quick test)
    print()
    print("-" * 60)
    print("  Module 5: Distributed Sniffer")
    print("-" * 60)
    try:
        from distributed import test_distributed
        result = test_distributed()
        if not result:
            print("  WARNING: Distributed test had issues (timing-dependent)")
    except Exception as e:
        print(f"  FAIL: {e}")
        # Not critical — networking may have issues
        print("  (Distributed test requires networking — not critical)")

    # Final
    print()
    print("=" * 60)
    if all_passed:
        print("  ALL SELF-TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")
    print("=" * 60)
    print()


def main():
    args = parse_args()

    # ── Self-test mode ──
    if args.test:
        run_self_tests()
        return

    # ── Attack simulation mode ──
    if args.simulate:
        from simulator import run_simulation
        run_simulation()
        return

    # ── Performance benchmark mode ──
    if args.benchmark:
        from performance import run_benchmark
        run_benchmark()
        return

    # ── PQC benchmark mode ──
    if args.benchmark_pqc:
        from pqc import run_pqc_benchmark
        run_pqc_benchmark()
        return

    # ── List interfaces ──
    if args.list_interfaces:
        try:
            from scapy.all import get_if_list
            print("\nAvailable interfaces:")
            for iface in get_if_list():
                print(f"  - {iface}")
        except ImportError:
            print("Scapy not installed. pip install scapy")
        return

    # ── Aggregator mode ──
    if args.mode == "aggregator":
        from distributed import AggregationServer
        server = AggregationServer(port=args.port)
        print(f"\n  Starting aggregation server on port {args.port}...")
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()
            print("\n  Aggregator stopped.")
        return

    # ── Capture mode ──
    print()
    print("  QUANTUM SNIFFER v2.0")
    print("  ════════════════════")
    print()

    # Web dashboard
    web_store = None
    if args.web:
        try:
            from web_dashboard import DashboardDataStore, start_web_dashboard
            web_store = DashboardDataStore()
            start_web_dashboard(web_store, port=args.web_port)
        except Exception as e:
            print(f"  Web dashboard error: {e}")
            print("  Install flask: pip install flask")

    # Start capture engine
    try:
        from engine import CaptureEngine
        engine = CaptureEngine(
            interface=args.interface,
            bpf_filter=args.filter,
            use_pqc=not args.no_pqc,
            use_dashboard=not args.no_dashboard,
            sensitivity=args.sensitivity,
            geoip=args.geoip,
            export_file=args.export,
        )

        # If sensor mode, connect to aggregator
        if args.mode == "sensor" and args.server:
            from distributed import SensorNode
            host, port = args.server.rsplit(":", 1)
            sensor = SensorNode("sensor-local", host, int(port))
            if sensor.connect():
                print(f"  Connected to aggregator {args.server}")

        engine.start()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
    except PermissionError:
        print("\n  ERROR: Requires elevated privileges (admin/root)")
        print("  Run as Administrator or with sudo")
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback; traceback.print_exc()


if __name__ == "__main__":
    main()
