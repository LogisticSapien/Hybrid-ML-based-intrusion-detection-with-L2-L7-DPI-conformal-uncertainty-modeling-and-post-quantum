"""
Distributed Sniffer
====================
Multi-node packet capture with central aggregation:
  • Sensor nodes: capture locally, stream summaries to aggregator
  • Aggregation server: receive from multiple sensors, unified IDS + analytics
  • JSON-over-TCP protocol with heartbeat monitoring
  • Node health tracking and status reporting
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict


@dataclass
class PacketSummary:
    """Serializable packet summary for network transport."""
    timestamp: float
    node_id: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int
    flags: str = ""
    info: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> 'PacketSummary':
        d = json.loads(data)
        return cls(**d)


@dataclass
class NodeStatus:
    """Health status of a sensor node."""
    node_id: str
    address: str
    last_heartbeat: float
    packets_sent: int
    uptime: float
    is_alive: bool = True

    @property
    def time_since_heartbeat(self) -> float:
        return time.time() - self.last_heartbeat


@dataclass
class DistributedMessage:
    """Wire protocol message."""
    msg_type: str  # "packet", "heartbeat", "register", "status"
    node_id: str
    payload: dict

    def serialize(self) -> bytes:
        data = json.dumps({
            "type": self.msg_type,
            "node_id": self.node_id,
            "payload": self.payload,
            "timestamp": time.time(),
        }).encode("utf-8")
        # Length-prefixed: 4-byte big-endian length + data
        return struct.pack("!I", len(data)) + data

    @classmethod
    def deserialize(cls, data: bytes) -> 'DistributedMessage':
        obj = json.loads(data.decode("utf-8"))
        return cls(
            msg_type=obj["type"],
            node_id=obj["node_id"],
            payload=obj.get("payload", {}),
        )


class AggregationServer:
    """Central aggregation server that receives from multiple sensor nodes."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.nodes: Dict[str, NodeStatus] = {}
        self.packet_queue: List[PacketSummary] = []
        self._lock = threading.Lock()
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._callbacks: List[Callable] = []

        # Statistics
        self.stats = {
            "total_packets": 0,
            "packets_by_node": defaultdict(int),
            "start_time": 0.0,
        }

    def on_packet(self, callback: Callable):
        """Register a callback for incoming packets."""
        self._callbacks.append(callback)

    def start(self):
        """Start the aggregation server."""
        self._running = True
        self.stats["start_time"] = time.time()

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(10)
        self._server_socket.settimeout(1.0)

        print(f"  Aggregation server listening on {self.host}:{self.port}")

        # Health monitor thread
        threading.Thread(target=self._health_monitor, daemon=True).start()

        # Accept loop
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        """Stop the server."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    def _handle_client(self, sock: socket.socket, addr):
        """Handle a sensor connection."""
        node_id = f"{addr[0]}:{addr[1]}"
        try:
            while self._running:
                # Read length prefix
                length_data = self._recv_exact(sock, 4)
                if not length_data:
                    break
                msg_len = struct.unpack("!I", length_data)[0]
                if msg_len > 1_000_000:  # Max 1MB
                    break

                msg_data = self._recv_exact(sock, msg_len)
                if not msg_data:
                    break

                msg = DistributedMessage.deserialize(msg_data)
                node_id = msg.node_id

                if msg.msg_type == "register":
                    with self._lock:
                        self.nodes[node_id] = NodeStatus(
                            node_id=node_id, address=f"{addr[0]}:{addr[1]}",
                            last_heartbeat=time.time(), packets_sent=0, uptime=0,
                        )
                    print(f"  Node registered: {node_id} from {addr}")

                elif msg.msg_type == "heartbeat":
                    with self._lock:
                        if node_id in self.nodes:
                            self.nodes[node_id].last_heartbeat = time.time()
                            self.nodes[node_id].uptime = msg.payload.get("uptime", 0)

                elif msg.msg_type == "packet":
                    pkt = PacketSummary(**msg.payload)
                    with self._lock:
                        self.packet_queue.append(pkt)
                        self.stats["total_packets"] += 1
                        self.stats["packets_by_node"][node_id] += 1
                        if node_id in self.nodes:
                            self.nodes[node_id].packets_sent += 1

                    for cb in self._callbacks:
                        try:
                            cb(pkt)
                        except Exception:
                            pass

        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            sock.close()
            with self._lock:
                if node_id in self.nodes:
                    self.nodes[node_id].is_alive = False

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except (socket.timeout, OSError):
                return None
        return data

    def _health_monitor(self):
        """Monitor node health via heartbeat timeout."""
        while self._running:
            time.sleep(5)
            with self._lock:
                for node in self.nodes.values():
                    if node.time_since_heartbeat > 15:
                        if node.is_alive:
                            node.is_alive = False
                            print(f"  Node {node.node_id} OFFLINE (no heartbeat for {node.time_since_heartbeat:.0f}s)")

    @property
    def summary(self) -> dict:
        with self._lock:
            alive = sum(1 for n in self.nodes.values() if n.is_alive)
            return {
                "total_nodes": len(self.nodes),
                "alive_nodes": alive,
                "total_packets": self.stats["total_packets"],
                "by_node": dict(self.stats["packets_by_node"]),
                "uptime": time.time() - self.stats["start_time"],
            }


class SensorNode:
    """Sensor node that captures packets and sends summaries to aggregator."""

    def __init__(self, node_id: str, server_host: str = "127.0.0.1", server_port: int = 9999):
        self.node_id = node_id
        self.server_host = server_host
        self.server_port = server_port
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._start_time = 0.0
        self.packets_sent = 0

    def connect(self) -> bool:
        """Connect to aggregation server."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self.server_host, self.server_port))
            self._start_time = time.time()
            self._running = True

            # Register
            msg = DistributedMessage("register", self.node_id, {"capabilities": ["capture", "ids"]})
            self._send(msg)

            # Start heartbeat
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()
            return True
        except (ConnectionRefusedError, OSError) as e:
            print(f"  Failed to connect to aggregator: {e}")
            return False

    def send_packet(self, summary: PacketSummary):
        """Send a packet summary to the aggregator."""
        if not self._running:
            return
        msg = DistributedMessage("packet", self.node_id, {
            "timestamp": summary.timestamp,
            "node_id": self.node_id,
            "protocol": summary.protocol,
            "src_ip": summary.src_ip,
            "dst_ip": summary.dst_ip,
            "src_port": summary.src_port,
            "dst_port": summary.dst_port,
            "size": summary.size,
            "flags": summary.flags,
            "info": summary.info,
        })
        self._send(msg)
        self.packets_sent += 1

    def disconnect(self):
        """Disconnect from aggregator."""
        self._running = False
        if self._sock:
            self._sock.close()

    def _send(self, msg: DistributedMessage):
        if self._sock:
            try:
                self._sock.sendall(msg.serialize())
            except (BrokenPipeError, OSError):
                self._running = False

    def _heartbeat_loop(self):
        while self._running:
            time.sleep(5)
            msg = DistributedMessage("heartbeat", self.node_id, {
                "uptime": time.time() - self._start_time,
                "packets_sent": self.packets_sent,
            })
            self._send(msg)


def test_distributed():
    """Self-test for distributed sniffer."""
    print("=" * 70)
    print("  DISTRIBUTED SNIFFER TEST")
    print("=" * 70)

    received = []

    def on_pkt(pkt):
        received.append(pkt)

    # Start server
    server = AggregationServer(port=0)  # OS-assigned port
    server.on_packet(on_pkt)

    # Find port
    import socket as _socket
    test_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    test_sock.bind(("127.0.0.1", 0))
    test_port = test_sock.getsockname()[1]
    test_sock.close()

    server.port = test_port
    srv_thread = threading.Thread(target=server.start, daemon=True)
    srv_thread.start()
    time.sleep(0.5)

    # Connect sensor
    sensor = SensorNode("sensor-1", "127.0.0.1", test_port)
    assert sensor.connect(), "Failed to connect"
    time.sleep(0.3)

    # Send packets
    for i in range(10):
        pkt = PacketSummary(
            timestamp=time.time(), node_id="sensor-1",
            protocol="TCP", src_ip=f"10.0.0.{i}",
            dst_ip="192.168.1.1", src_port=40000+i,
            dst_port=80, size=100+i*10,
        )
        sensor.send_packet(pkt)
    time.sleep(1)

    # Verify
    sensor.disconnect()
    server.stop()

    print(f"\n  Packets sent: 10")
    print(f"  Packets received: {len(received)}")
    print(f"  Nodes registered: {len(server.nodes)}")
    summary = server.summary
    print(f"  Server summary: {summary}")

    success = len(received) >= 8  # Allow for timing
    print(f"\n  {'OK' if success else 'FAIL'} Distributed test {'PASSED' if success else 'FAILED'}")
    return success


if __name__ == "__main__":
    test_distributed()
