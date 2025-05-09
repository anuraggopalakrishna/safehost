import pyshark
import time
from datetime import datetime
import numpy as np
import sqlite3
from threading import Lock
import warnings
import joblib
import os
import pandas as pd


warnings.filterwarnings("ignore")


class TrafficSniffer:
    def __init__(
        self,
        interface="\\Device\\NPF_Loopback",
        db_file="network_traffic.db",
        model_path="model.pkl",
        prediction_interval=5,
    ):
        self.interface = interface
        self.flows = {}
        self.flow_timeout = 120  # seconds
        self.last_cleanup = time.time()
        self.last_prediction = time.time()
        self.prediction_interval = prediction_interval
        self.db_file = db_file
        self.db_lock = Lock()

        # Model components
        self.model = None
        self.scaler = None
        self.label_encoder = None

        # Load model if exists
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
            if not self.model:
                print("WARNING: Continuing without ML model")
        else:
            print(f"Model file not found at {model_path}. Continuing without ML model.")

        self._init_db()

    def _load_model(self, model_path):
        """Load the trained ML model and components"""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data["model"]
            self.scaler = model_data["scaler"]
            self.label_encoder = model_data["label_encoder"]
            print("ML model and components loaded successfully")
        except Exception as e:
            print(f"Error loading model: {e}")

    # Add this to your TrafficSniffer class to create a function that exports data for Grafana

    def export_for_grafana(
        self, db_file="network_traffic.db", csv_file="grafana_export.csv"
    ):
        """Export data in a Grafana-friendly format"""
        with sqlite3.connect(db_file) as conn:
            df = pd.read_sql(
                """
                SELECT 
                    timestamp,
                    flow_key,
                    label as prediction,
                    prediction_confidence,
                    flow_bytes_s as bytes_per_sec,
                    flow_packets_s as packets_per_sec,
                    duration,
                    fwd_packets,
                    bwd_packets,
                    init_fwd_win,
                    init_bwd_win
                FROM flow_stats
                ORDER BY timestamp DESC
                LIMIT 10000
            """,
                conn,
            )

        # Convert timestamp to Grafana's preferred format
        df["timestamp"] = pd.to_datetime(df["timestamp"]).astype("int64") // 10**6
        df.to_csv(csv_file, index=False)
        print(f"Data exported to {csv_file} for Grafana")

    def _init_db(self):
        """Initialize the SQLite database"""
        with self.db_lock, sqlite3.connect(self.db_file) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS flow_stats (
                    timestamp DATETIME,
                    flow_key TEXT,
                    duration REAL,
                    fwd_packets INTEGER,
                    bwd_packets INTEGER,
                    fwd_bytes INTEGER,
                    bwd_bytes INTEGER,
                    flow_bytes_s REAL,
                    flow_packets_s REAL,
                    fwd_iat_mean REAL,
                    bwd_iat_mean REAL,
                    fwd_header_len INTEGER,
                    bwd_header_len INTEGER,
                    fin_flag_count INTEGER,
                    syn_flag_count INTEGER,
                    ack_flag_count INTEGER,
                    init_fwd_win INTEGER,
                    init_bwd_win INTEGER,
                    label TEXT,
                    label_encoded INTEGER,
                    prediction_confidence REAL
                )
                """
            )
            # Create indexes for performance
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON flow_stats(timestamp)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_label ON flow_stats(label)")
            conn.commit()

    def _save_flow_to_db(self, flow_data):
        """Save flow statistics to the database"""
        with self.db_lock, sqlite3.connect(self.db_file) as conn:
            conn.execute(
                """
                INSERT INTO flow_stats VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    datetime.now(),
                    flow_data["flow_key"],
                    flow_data["duration"],
                    flow_data["fwd_packets"],
                    flow_data["bwd_packets"],
                    flow_data["fwd_bytes"],
                    flow_data["bwd_bytes"],
                    flow_data["flow_bytes_s"],
                    flow_data["flow_packets_s"],
                    flow_data["fwd_iat_mean"],
                    flow_data["bwd_iat_mean"],
                    flow_data["fwd_header_len"],
                    flow_data["bwd_header_len"],
                    flow_data["fin_flag_count"],
                    flow_data["syn_flag_count"],
                    flow_data["ack_flag_count"],
                    flow_data["init_fwd_win"],
                    flow_data["init_bwd_win"],
                    flow_data["label"],
                    flow_data.get("label_encoded", -1),
                    flow_data.get("prediction_confidence", 0.0),
                ),
            )
            conn.commit()

    def _get_ip_info(self, packet):
        """Extract IP information handling both IPv4 and IPv6"""
        if hasattr(packet, "ip"):
            return (
                getattr(packet.ip, "src", "0.0.0.0"),
                getattr(packet.ip, "dst", "0.0.0.0"),
                int(getattr(packet.ip, "hdr_len", 20)) * 4,
            )
        elif hasattr(packet, "ipv6"):
            return (
                getattr(packet.ipv6, "src", "::"),
                getattr(packet.ipv6, "dst", "::"),
                40,
            )
        return ("::", "::", 0)

    def _get_transport_info(self, packet):
        """Extract transport layer information"""
        src_port = dst_port = "0"
        transport_len = 0
        win_size = 0

        if hasattr(packet, "tcp"):
            src_port = str(getattr(packet.tcp, "srcport", "0"))
            dst_port = str(getattr(packet.tcp, "dstport", "0"))
            transport_len = int(getattr(packet.tcp, "hdr_len", 5)) * 4
            win_size = int(getattr(packet.tcp, "window_size_value", 0))
        elif hasattr(packet, "udp"):
            src_port = str(getattr(packet.udp, "srcport", "0"))
            dst_port = str(getattr(packet.udp, "dstport", "0"))
            transport_len = 8

        return src_port, dst_port, transport_len, win_size

    def _get_packet_length(self, packet):
        """Safely get packet length from different possible locations"""
        if hasattr(packet, "length"):
            return int(packet.length)
        elif hasattr(packet, "ip") and hasattr(packet.ip, "len"):
            return int(packet.ip.len)
        elif hasattr(packet, "ipv6") and hasattr(packet.ipv6, "plen"):
            return int(packet.ipv6.plen) + 40
        return 0

    def _predict_with_model(self, flow_data):
        """Use the ML model to predict based on flow features"""
        if not self.model:
            return "MODEL_NOT_LOADED", -1, 0.0

        try:
            # Prepare features in the exact order used during training
            features = np.array(
                [
                    flow_data["duration"],  # Flow Duration
                    flow_data["fwd_packets"],  # Total Fwd Packets
                    flow_data["bwd_packets"],  # Total Backward Packets
                    flow_data["fwd_bytes"],  # Fwd Packets Length Total
                    flow_data["bwd_bytes"],  # Bwd Packets Length Total
                    flow_data["flow_bytes_s"],  # Flow Bytes/s
                    flow_data["flow_packets_s"],  # Flow Packets/s
                    (flow_data["fwd_iat_mean"] + flow_data["bwd_iat_mean"])
                    / 2,  # Flow IAT Mean
                    flow_data["fwd_iat_mean"],  # Fwd IAT Mean
                    flow_data["bwd_iat_mean"],  # Bwd IAT Mean
                    flow_data["fwd_header_len"],  # Fwd Header Length
                    flow_data["bwd_header_len"],  # Bwd Header Length
                    (flow_data["fwd_bytes"] + flow_data["bwd_bytes"])
                    / max(
                        1, (flow_data["fwd_packets"] + flow_data["bwd_packets"])
                    ),  # Packet Length Mean
                    flow_data["fin_flag_count"],  # FIN Flag Count
                    flow_data["syn_flag_count"],  # SYN Flag Count
                    flow_data["ack_flag_count"],  # ACK Flag Count
                    flow_data["init_fwd_win"],  # Init Fwd Win Bytes
                    flow_data["init_bwd_win"],  # Init Bwd Win Bytes
                ]
            ).reshape(1, -1)

            # Scale features
            features_scaled = self.scaler.transform(features)

            # Make prediction
            prediction_encoded = self.model.predict(features_scaled)[0]
            confidence = np.max(self.model.predict_proba(features_scaled))
            prediction_label = self.label_encoder.inverse_transform(
                [prediction_encoded]
            )[0]

            return prediction_label, prediction_encoded, confidence

        except Exception as e:
            print(f"Prediction error: {e}")
            return "PREDICTION_ERROR", -1, 0.0

    def _finalize_flow(self, flow_key):
        """Finalize and save flow statistics"""
        if flow_key not in self.flows:
            return

        flow = self.flows[flow_key]
        flow_duration = max(flow["last_time"] - flow["start_time"], 0.001)
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        total_packets = flow["fwd_packets"] + flow["bwd_packets"]

        flow_data = {
            "flow_key": flow_key,
            "duration": flow_duration,
            "fwd_packets": flow["fwd_packets"],
            "bwd_packets": flow["bwd_packets"],
            "fwd_bytes": flow["fwd_bytes"],
            "bwd_bytes": flow["bwd_bytes"],
            "flow_bytes_s": total_bytes / flow_duration,
            "flow_packets_s": total_packets / flow_duration,
            "fwd_iat_mean": np.mean(flow["fwd_iat"]) if flow["fwd_iat"] else 0,
            "bwd_iat_mean": np.mean(flow["bwd_iat"]) if flow["bwd_iat"] else 0,
            "fwd_header_len": flow["fwd_header_len"],
            "bwd_header_len": flow["bwd_header_len"],
            "fin_flag_count": flow["flags"]["FIN"],
            "syn_flag_count": flow["flags"]["SYN"],
            "ack_flag_count": flow["flags"]["ACK"],
            "init_fwd_win": flow["init_fwd_win"],
            "init_bwd_win": flow["init_bwd_win"],
            "label": "Benign",
            "label_encoded": -1,
        }

        # Get ML model prediction if enabled
        if self.model and (
            time.time() - self.last_prediction >= self.prediction_interval
        ):
            label, label_encoded, confidence = self._predict_with_model(flow_data)
            flow_data["label"] = label
            flow_data["label_encoded"] = label_encoded
            flow_data["prediction_confidence"] = confidence
            self.last_prediction = time.time()

        self._save_flow_to_db(flow_data)
        del self.flows[flow_key]

    def _cleanup_inactive_flows(self):
        """Periodically clean up inactive flows"""
        current_time = time.time()
        if current_time - self.last_cleanup > 30:  # Cleanup every 30 seconds
            inactive_flows = [
                k
                for k, v in self.flows.items()
                if current_time - v["last_time"] > self.flow_timeout
            ]
            for flow_key in inactive_flows:
                self._finalize_flow(flow_key)
            self.last_cleanup = current_time

    def extract_features(self, packet):
        try:
            if not (hasattr(packet, "ip") or hasattr(packet, "ipv6")):
                return

            self._cleanup_inactive_flows()

            src_ip, dst_ip, ip_header_len = self._get_ip_info(packet)
            src_port, dst_port, transport_len, win_size = self._get_transport_info(
                packet
            )
            packet_length = self._get_packet_length(packet)
            total_header_len = ip_header_len + transport_len

            # Create canonical flow key
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                direction = "fwd"
            else:
                flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                direction = "bwd"

            current_time = getattr(
                packet.sniff_time, "timestamp", lambda: time.time()
            )()

            # Initialize new flow if not present
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    "start_time": current_time,
                    "last_time": current_time,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "fwd_iat": [],
                    "bwd_iat": [],
                    "fwd_header_len": 0,
                    "bwd_header_len": 0,
                    "flags": {"FIN": 0, "SYN": 0, "ACK": 0, "RST": 0},
                    "init_fwd_win": 0,
                    "init_bwd_win": 0,
                    "protocol": "TCP" if hasattr(packet, "tcp") else "UDP",
                }

            flow = self.flows[flow_key]
            prev_time = flow["last_time"]

            # Update flow statistics
            flow[f"{direction}_packets"] += 1
            flow[f"{direction}_bytes"] += packet_length
            flow[f"{direction}_header_len"] += total_header_len

            # Update inter-arrival times
            if flow[f"{direction}_packets"] > 1:
                flow[f"{direction}_iat"].append(current_time - prev_time)

            # Update TCP flags
            if hasattr(packet, "tcp") and hasattr(packet.tcp, "flags"):
                flags = str(packet.tcp.flags)
                for flag in flow["flags"]:
                    if flag in flags:
                        flow["flags"][flag] += 1

            # Update initial window size for the first packet in each direction
            if direction == "fwd" and flow["init_fwd_win"] == 0 and win_size > 0:
                flow["init_fwd_win"] = win_size
            elif direction == "bwd" and flow["init_bwd_win"] == 0 and win_size > 0:
                flow["init_bwd_win"] = win_size

            flow["last_time"] = current_time

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def start_live_capture(self):
        """Start capturing network traffic"""
        print(f"Starting live capture on {self.interface}...")
        print(f"ML model {'loaded' if self.model else 'not loaded'}")

        capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter="tcp or udp",
            use_json=True,
            include_raw=False,
        )

        try:
            for packet in capture.sniff_continuously():
                self.extract_features(packet)
        except KeyboardInterrupt:
            print("\nStopping capture...")
        finally:
            capture.close()
            # Finalize all remaining flows before exiting
            for flow_key in list(self.flows.keys()):
                self._finalize_flow(flow_key)
            print("Capture stopped and all flows saved to database.")

    def start_grafana_exporter(self, interval=300):
        """Periodically export data for Grafana"""

        def exporter():
            while True:
                self.export_for_grafana()
                time.sleep(interval)

        import threading

        thread = threading.Thread(target=exporter, daemon=True)
        thread.start()


if __name__ == "__main__":

    sniffer = TrafficSniffer(
        interface="\\Device\\NPF_Loopback",
        model_path="model.pkl",
        prediction_interval=5,
    )
    sniffer.start_live_capture()

