import os
import io
import json
import pickle
import joblib
import time
import threading
import numpy as np
import pandas as pd
import requests
from datetime import datetime, timezone
from kafka import KafkaConsumer
from tensorflow.keras.models import load_model

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "flows")
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.80"))
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
SOURCE_TYPE = os.getenv("SOURCE_TYPE", "website")
REGISTERED_ID = os.getenv("REGISTERED_ID", "1")
HEALTH_INTERVAL = int(os.getenv("HEALTH_INTERVAL", "10"))

# ── WHITELIST ─────────────────────────────────────────────────────────────────

WHITELIST_IPS = {
    "172.20.0.101",
    "172.20.0.102",
    "172.20.0.103",
    "168.63.129.16",   # Azure infrastructure health probe
    "127.0.0.1",       # Localhost
    "39.34.170.230",   # Admin browser IP
}
for ip in os.getenv("EXTRA_WHITELIST_IPS", "").split(","):
    if ip.strip():
        WHITELIST_IPS.add(ip.strip())

# ── RECOMMENDED ACTIONS ───────────────────────────────────────────────────────

RECOMMENDED_ACTIONS_WEBSITE = {
    "PortScan": "Block source IP in firewall. Review open ports on target. Disable unnecessary services.",
    "SQL-Injection": "Review and sanitize all database queries. Enable WAF rules. Check for unauthorized data access.",
    "BruteForce-Web": "Implement rate limiting on login endpoint. Enable account lockout after 5 failed attempts. Consider 2FA.",
    "DoS-Slowloris": "Configure connection timeout limits on web server. Enable rate limiting. Consider CDN protection.",
    "DDoS": "Enable DDoS protection. Contact ISP. Consider CDN like Cloudflare.",
    "BruteForce-XSS": "Implement Content Security Policy headers. Sanitize all user inputs. Enable XSS filtering.",
    "Bot": "Implement CAPTCHA. Block suspicious user agents. Enable bot protection.",
    "Infiltration": "Isolate affected system immediately. Review access logs. Change all credentials.",
    "FTP-BruteForce": "Disable FTP if not needed. Use SFTP instead. Implement rate limiting on FTP login.",
    "SSH-BruteForce": "Disable password authentication. Use SSH keys only. Change default SSH port.",
    "DoS-Hulk": "Enable rate limiting. Configure web server connection limits. Consider CDN protection.",
    "DoS-GoldenEye": "Enable rate limiting. Configure connection timeouts. Block suspicious user agents.",
    "DoS-SlowHTTPTest": "Configure minimum data rate limits. Enable connection timeouts on web server.",
    "Heartbleed": "Update OpenSSL immediately. Revoke and reissue all SSL certificates.",
}

RECOMMENDED_ACTIONS_IOT = {
    "Reconnaissance & Access Attack": "Isolate affected IoT devices. Review network access controls. Change default credentials on all devices.",
    "backdoor": "Immediately isolate affected device. Perform factory reset. Update firmware. Review network logs.",
    "ransomware": "Disconnect affected devices immediately. Do not pay ransom. Restore from backup. Report to authorities.",
    "mitm": "Enable encrypted communications on all IoT devices. Implement certificate pinning. Review ARP tables.",
}

# ── IOT LABEL MAPPING ─────────────────────────────────────────────────────────
# Human-readable names for the ORIGINAL class codes the model was trained on.
# nexa_label_encoder.pkl.classes_ holds those codes (e.g. [0,1,2,4,5]) in
# model-index order, so the model index -> code -> name chain is:
#   model.predict() -> i  ->  encoder.classes_[i] (code)  ->  IOT_CODE_NAMES[code]
IOT_CODE_NAMES = {
    0: "Benign",
    1: "Reconnaissance & Access Attack",
    2: "backdoor",
    4: "mitm",
    5: "ransomware",
}
# Index -> name map actually used by predict_iot; built from the encoder at model
# load time (see the IoT branch below). Empty until then.
IOT_LABEL_MAPPING = {}

# ── RAW COLUMNS (CICFlowMeter output) ─────────────────────────────────────────

RAW_COLUMNS = [
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
    "Timestamp", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min",
    "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts",
    "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
]

# ── WEBSITE MODEL FEATURES ────────────────────────────────────────────────────

WEBSITE_FEATURE_COLS = [
    "Dst Port", "Protocol", "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packets/s", "Bwd Packets/s", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Packet Length Max",
    "Packet Length Min", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "Fwd Header Length", "Bwd Header Length",
    "Fwd Seg Size Min", "Fwd Act Data Pkts", "Flow IAT Mean", "Flow IAT Max",
    "Flow IAT Min", "Flow IAT Std", "Fwd IAT Total", "Fwd IAT Max", "Fwd IAT Min",
    "Fwd IAT Mean", "Fwd IAT Std", "Bwd IAT Total", "Bwd IAT Max", "Bwd IAT Min",
    "Bwd IAT Mean", "Bwd IAT Std", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Active Mean", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# ── IOT MODEL FEATURES ────────────────────────────────────────────────────────

IOT_FEATURE_COLS = [
    'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
    'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
    'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
    'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
    'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
    'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
    'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
    'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# ── CICFlowMeter → TON-IoT column name mapping ───────────────────────────────

CICFLOW_TO_TONIOT = {
    "Protocol":                   "Protocol",
    "Flow Duration":              "Flow Duration",
    "Total Fwd Packet":           "Tot Fwd Pkts",
    "Total Bwd packets":          "Tot Bwd Pkts",
    "Total Length of Fwd Packet": "TotLen Fwd Pkts",
    "Total Length of Bwd Packet": "TotLen Bwd Pkts",
    "Fwd Packet Length Max":      "Fwd Pkt Len Max",
    "Fwd Packet Length Min":      "Fwd Pkt Len Min",
    "Fwd Packet Length Mean":     "Fwd Pkt Len Mean",
    "Fwd Packet Length Std":      "Fwd Pkt Len Std",
    "Bwd Packet Length Max":      "Bwd Pkt Len Max",
    "Bwd Packet Length Min":      "Bwd Pkt Len Min",
    "Bwd Packet Length Mean":     "Bwd Pkt Len Mean",
    "Bwd Packet Length Std":      "Bwd Pkt Len Std",
    "Flow Bytes/s":               "Flow Byts/s",
    "Flow Packets/s":             "Flow Pkts/s",
    "Flow IAT Mean":              "Flow IAT Mean",
    "Flow IAT Std":               "Flow IAT Std",
    "Flow IAT Max":               "Flow IAT Max",
    "Flow IAT Min":               "Flow IAT Min",
    "Fwd IAT Total":              "Fwd IAT Tot",
    "Fwd IAT Mean":               "Fwd IAT Mean",
    "Fwd IAT Std":                "Fwd IAT Std",
    "Fwd IAT Max":                "Fwd IAT Max",
    "Fwd IAT Min":                "Fwd IAT Min",
    "Bwd IAT Total":              "Bwd IAT Tot",
    "Bwd IAT Mean":               "Bwd IAT Mean",
    "Bwd IAT Std":                "Bwd IAT Std",
    "Bwd IAT Max":                "Bwd IAT Max",
    "Bwd IAT Min":                "Bwd IAT Min",
    "Fwd PSH Flags":              "Fwd PSH Flags",
    "Bwd PSH Flags":              "Bwd PSH Flags",
    "Fwd URG Flags":              "Fwd URG Flags",
    "Bwd URG Flags":              "Bwd URG Flags",
    "Fwd Header Length":          "Fwd Header Len",
    "Bwd Header Length":          "Bwd Header Len",
    "Fwd Packets/s":              "Fwd Pkts/s",
    "Bwd Packets/s":              "Bwd Pkts/s",
    "Packet Length Min":          "Pkt Len Min",
    "Packet Length Max":          "Pkt Len Max",
    "Packet Length Mean":         "Pkt Len Mean",
    "Packet Length Std":          "Pkt Len Std",
    "Packet Length Variance":     "Pkt Len Var",
    "FIN Flag Count":             "FIN Flag Cnt",
    "SYN Flag Count":             "SYN Flag Cnt",
    "RST Flag Count":             "RST Flag Cnt",
    "PSH Flag Count":             "PSH Flag Cnt",
    "ACK Flag Count":             "ACK Flag Cnt",
    "URG Flag Count":             "URG Flag Cnt",
    "CWR Flag Count":             "CWE Flag Count",
    "ECE Flag Count":             "ECE Flag Cnt",
    "Down/Up Ratio":              "Down/Up Ratio",
    "Average Packet Size":        "Pkt Size Avg",
    "Fwd Segment Size Avg":       "Fwd Seg Size Avg",
    "Bwd Segment Size Avg":       "Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg":         "Fwd Byts/b Avg",
    "Fwd Packet/Bulk Avg":        "Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg":          "Fwd Blk Rate Avg",
    "Bwd Bytes/Bulk Avg":         "Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg":        "Bwd Pkts/b Avg",
    "Bwd Bulk Rate Avg":          "Bwd Blk Rate Avg",
    "Subflow Fwd Packets":        "Subflow Fwd Pkts",
    "Subflow Fwd Bytes":          "Subflow Fwd Byts",
    "Subflow Bwd Packets":        "Subflow Bwd Pkts",
    "Subflow Bwd Bytes":          "Subflow Bwd Byts",
    "FWD Init Win Bytes":         "Init Fwd Win Byts",
    "Bwd Init Win Bytes":         "Init Bwd Win Byts",
    "Fwd Act Data Pkts":          "Fwd Act Data Pkts",
    "Fwd Seg Size Min":           "Fwd Seg Size Min",
    "Active Mean":                "Active Mean",
    "Active Std":                 "Active Std",
    "Active Max":                 "Active Max",
    "Active Min":                 "Active Min",
    "Idle Mean":                  "Idle Mean",
    "Idle Std":                   "Idle Std",
    "Idle Max":                   "Idle Max",
    "Idle Min":                   "Idle Min",
}

# ── LOAD MODELS ───────────────────────────────────────────────────────────────

print(f"Source type: {SOURCE_TYPE}")

if SOURCE_TYPE == "website":
    print("Loading website CNN model...")
    website_model = load_model("/app/model/cnn_finetuned_v2.keras")

    print("Loading website scaler...")
    with open("/app/model/scaler.pkl", "rb") as f:
        website_scaler = pickle.load(f)

    print("Loading website label mapping...")
    with open("/app/model/label_mapping.json", "r") as f:
        website_label_mapping = json.load(f)

    print("Website model loaded!")

else:
    print("Loading IoT XGBoost model...")
    with open("/app/model/nexa_xgb_model.pkl", "rb") as f:
        iot_model = pickle.load(f)

    print("Loading IoT scaler...")
    iot_scaler = joblib.load("/app/model/nexa_scalar.pkl")

    # Build the index -> name map from the label encoder (authoritative source of
    # the model-index -> original-code relationship), combined with IOT_CODE_NAMES.
    # Falls back to positional names (but logs loudly) if the artifacts disagree,
    # so a swapped/retrained model can never silently mislabel.
    try:
        iot_encoder = joblib.load("/app/model/nexa_label_encoder.pkl")
        codes = list(iot_encoder.classes_)
        unmapped = [c for c in codes if int(c) not in IOT_CODE_NAMES]
        model_n = len(getattr(iot_model, "classes_", codes))
        if unmapped or len(codes) != model_n:
            print(f"WARNING: encoder/model/name-table mismatch "
                  f"(encoder codes={codes}, model n_classes={model_n}, "
                  f"unmapped={unmapped}); falling back to positional names")
            IOT_LABEL_MAPPING = {i: n for i, n in enumerate(IOT_CODE_NAMES.values())}
        else:
            IOT_LABEL_MAPPING = {i: IOT_CODE_NAMES[int(c)] for i, c in enumerate(codes)}
    except Exception as e:
        print(f"WARNING: could not load label encoder ({e}); "
              f"using positional names from IOT_CODE_NAMES")
        IOT_LABEL_MAPPING = {i: n for i, n in enumerate(IOT_CODE_NAMES.values())}

    print("IoT model loaded!")
    print(f"IoT label mapping (index -> name): {IOT_LABEL_MAPPING}")

print(f"Backend URL: {BACKEND_URL}")
print(f"Confidence threshold: {CONFIDENCE_THRESHOLD}")
print("All artifacts loaded! Ready to consume.")

# ── METRICS ───────────────────────────────────────────────────────────────────

metrics = {
    "flows_processed": 0,
    "alerts_triggered": 0,
    "last_batch_time": None,
    "start_time": datetime.now(timezone.utc).isoformat(),
    "last_fpm": 0,
    "last_apm": 0,
    "last_update_ts": 0
}

flow_history = []
alert_history = []
history_lock = threading.Lock()

def add_to_history(f_count, a_count):
    now = time.time()
    with history_lock:
        flow_history.append((now, f_count))
        alert_history.append((now, a_count))
        cutoff = now - 60
        while flow_history and flow_history[0][0] < cutoff:
            flow_history.pop(0)
        f_total = sum(count for ts, count in flow_history if ts >= cutoff)
        a_total = sum(count for ts, count in alert_history if ts >= cutoff)
        metrics["last_fpm"] = f_total
        metrics["last_apm"] = a_total
        metrics["last_update_ts"] = now

def get_rolling_metrics():
    return metrics["last_fpm"], metrics["last_apm"]

# ── HELPERS ───────────────────────────────────────────────────────────────────

def get_severity(prediction, confidence):
    if prediction == "Benign":
        return "NORMAL"
    if confidence >= 0.95:
        return "CRITICAL"
    elif confidence >= 0.85:
        return "HIGH"
    elif confidence >= 0.80:
        return "MEDIUM"
    else:
        return "LOW"

def get_recommended_action(label, is_alert):
    if not is_alert:
        return ""
    if SOURCE_TYPE == "website":
        return RECOMMENDED_ACTIONS_WEBSITE.get(label, "Investigate the source IP and review network logs.")
    else:
        return RECOMMENDED_ACTIONS_IOT.get(label, "Isolate affected IoT device and review network logs.")

# ── PREPROCESSING ─────────────────────────────────────────────────────────────

def preprocess_batch(batch_str):
    try:
        rows = [line for line in batch_str.strip().split('\n') if line.strip()]
        if not rows:
            return None, None

        df_raw = pd.read_csv(
            io.StringIO('\n'.join(rows)),
            header=None,
            names=RAW_COLUMNS,
            low_memory=False
        )
        df_raw.columns = df_raw.columns.str.strip()

        metadata = df_raw[["Src IP", "Dst IP", "Dst Port", "Protocol",
                            "Timestamp", "Flow Duration", "Flow Bytes/s",
                            "Flow Packets/s", "Total Fwd Packet",
                            "Total Bwd packets"]].copy()

        df_raw = df_raw[
            (df_raw['Flow Duration'] > 0) &
            (df_raw['Flow Bytes/s'] >= 0) &
            (df_raw['Flow Packets/s'] >= 0)
        ]
        metadata = metadata.loc[df_raw.index]

        df_raw['FWD Init Win Bytes'] = pd.to_numeric(
            df_raw['FWD Init Win Bytes'], errors='coerce').replace(-1, 0)
        df_raw['Bwd Init Win Bytes'] = pd.to_numeric(
            df_raw['Bwd Init Win Bytes'], errors='coerce').replace(-1, 0)

        return df_raw, metadata.reset_index(drop=True)

    except Exception as e:
        print(f"Preprocessing error: {e}")
        return None, None

def extract_website_features(df_raw):
    missing = [c for c in WEBSITE_FEATURE_COLS if c not in df_raw.columns]
    if missing:
        print(f"WARNING: Missing website columns: {missing}")
        return None

    df_features = df_raw[WEBSITE_FEATURE_COLS].copy()
    for col in WEBSITE_FEATURE_COLS:
        df_features[col] = pd.to_numeric(df_features[col], errors='coerce')
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_features.dropna(inplace=True)
    return df_features

def extract_iot_features(df_raw):
    df_renamed = df_raw.rename(columns=CICFLOW_TO_TONIOT)

    missing = [c for c in IOT_FEATURE_COLS if c not in df_renamed.columns]
    if missing:
        print(f"WARNING: Missing IoT columns: {missing}")
        return None

    df_features = df_renamed[IOT_FEATURE_COLS].copy()
    for col in IOT_FEATURE_COLS:
        df_features[col] = pd.to_numeric(df_features[col], errors='coerce')
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_features.dropna(inplace=True)
    return df_features

# ── PREDICTION ────────────────────────────────────────────────────────────────

def predict_website(df_features, metadata):
    X = website_scaler.transform(df_features[WEBSITE_FEATURE_COLS])
    X_cnn = X.reshape(X.shape[0], X.shape[1], 1)
    predictions = website_model.predict(X_cnn, verbose=0)
    class_indices = np.argmax(predictions, axis=1)
    confidences = np.max(predictions, axis=1)

    results = []
    now = datetime.now(timezone.utc)

    for i, (cls_idx, conf) in enumerate(zip(class_indices, confidences)):
        label = website_label_mapping[str(cls_idx)]
        meta = metadata.iloc[i] if i < len(metadata) else {}
        src_ip = str(meta.get("Src IP", "")).strip() or ""
        dst_ip = str(meta.get("Dst IP", "")).strip() or ""

        flow_duration = float(meta.get("Flow Duration", 0))
        flow_packets_per_sec = float(meta.get("Flow Packets/s", 0))
        dst_port = int(meta.get("Dst Port", 0))
        src_port = int(meta.get("Src Port", 0))

        # Whitelist benign infrastructure, pipeline broker ports, and admin management traffic
        is_pipeline_port = (
            dst_port in {29092, 9092, 9093, 8000, 3000, 3306} or
            src_port in {29092, 9092, 9093, 8000, 3000, 3306}
        )
        is_whitelisted = (
            is_pipeline_port or
            src_ip in WHITELIST_IPS or dst_ip in WHITELIST_IPS or
            src_ip.startswith("39.34.") or dst_ip.startswith("39.34.") or
            src_ip == "172.16.0.4" or dst_ip == "172.16.0.4" or
            src_ip == "168.63.129.16" or dst_ip == "168.63.129.16"
        )
        if is_whitelisted:
            label = "Benign"
            conf = 1.0

        if label == "DoS-Slowloris":
            if flow_duration < 5.0 or flow_packets_per_sec > 10.0:
                label = "Benign"
                conf = 1.0

        is_alert = label != "Benign" and float(conf) >= CONFIDENCE_THRESHOLD
        severity = get_severity(label, float(conf))
        results.append(_build_result(label, conf, is_alert, severity, meta, now))

    return results

def predict_iot(df_features, metadata):
    X = iot_scaler.transform(df_features[IOT_FEATURE_COLS])
    predictions = iot_model.predict(X)

    try:
        proba = iot_model.predict_proba(X)
        confidences = np.max(proba, axis=1)
    except:
        confidences = np.ones(len(predictions))

    # Use verified manual mapping instead of broken encoder
    labels = [IOT_LABEL_MAPPING.get(int(p), "Unknown") for p in predictions]

    results = []
    now = datetime.now(timezone.utc)

    for i, (label, conf) in enumerate(zip(labels, confidences)):
        meta = metadata.iloc[i] if i < len(metadata) else {}
        src_ip = str(meta.get("Src IP", "")).strip() or None

        if src_ip in WHITELIST_IPS:
            label = "Benign"
            conf = 1.0

        is_alert = label != "Benign" and float(conf) >= CONFIDENCE_THRESHOLD
        severity = get_severity(label, float(conf))
        results.append(_build_result(label, conf, is_alert, severity, meta, now))

    return results

def _build_result(label, conf, is_alert, severity, meta, now):
    src_ip = str(meta.get("Src IP", "")).strip() or None
    dst_ip = str(meta.get("Dst IP", "")).strip() or None
    dst_port = int(meta.get("Dst Port", 0))
    protocol = int(meta.get("Protocol", 0))
    flow_duration = float(meta.get("Flow Duration", 0))
    flow_bytes_per_sec = float(meta.get("Flow Bytes/s", 0))
    flow_packets_per_sec = float(meta.get("Flow Packets/s", 0))
    total_fwd_packets = int(meta.get("Total Fwd Packet", 0))
    total_bwd_packets = int(meta.get("Total Bwd packets", 0))

    raw_ts = str(meta.get("Timestamp", ""))
    try:
        ts_dt = pd.to_datetime(raw_ts, utc=True)
        if (now - ts_dt).total_seconds() > 3600:
            ts = now.isoformat()
        else:
            ts = ts_dt.isoformat()
    except:
        ts = now.isoformat()

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "prediction": label,
        "confidence": round(float(conf), 4),
        "is_alert": is_alert,
        "severity": severity,
        "flow_duration": flow_duration,
        "flow_bytes_per_sec": round(flow_bytes_per_sec, 4),
        "flow_packets_per_sec": round(flow_packets_per_sec, 4),
        "total_fwd_packets": total_fwd_packets,
        "total_bwd_packets": total_bwd_packets,
        "source_type": SOURCE_TYPE,
        "registered_id": REGISTERED_ID,
        "recommended_action": get_recommended_action(label, is_alert)
    }

# ── BACKEND ───────────────────────────────────────────────────────────────────

def send_to_backend(results):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/flows/ingest/",
            json={"source_type": SOURCE_TYPE, "flows": results},
            timeout=10
        )
        if response.status_code != 200:
            print(f"Backend error: {response.status_code} — {response.text[:100]}")
    except requests.exceptions.ConnectionError:
        print("Backend not reachable — skipping this batch")
    except Exception as e:
        print(f"Send error: {e}")

# ── HEALTH REPORTER ───────────────────────────────────────────────────────────

def report_health():
    while True:
        try:
            fpm, apm = get_rolling_metrics()
            health_data = {
                "component": "ml-consumer",
                "status": True,
                "flows_processed": metrics["flows_processed"],
                "alerts_triggered": metrics["alerts_triggered"],
                "flows_per_minute": fpm,
                "alerts_per_minute": apm,
                "last_batch_time": metrics["last_batch_time"],
                "uptime_since": metrics["start_time"],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            requests.post(
                f"{BACKEND_URL}/api/health/pipeline/",
                json=health_data,
                timeout=5
            )
        except Exception as e:
            print(f"Health report error: {e}")
        time.sleep(HEALTH_INTERVAL)

health_thread = threading.Thread(target=report_health, daemon=True)
health_thread.start()

# ── KAFKA CONSUMER LOOP ───────────────────────────────────────────────────────

print(f"Connecting to Kafka at {KAFKA_BROKER}...")

try:
    dynamic_group_id = f"ml-consumer-group-{int(time.time())}"
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        auto_offset_reset='latest',
        enable_auto_commit=True,
        group_id=dynamic_group_id,
        value_deserializer=lambda x: x.decode('utf-8')
    )
    print("Connected! Waiting for messages...")
except Exception as e:
    print(f"Critical Error: Failed to connect to Kafka: {e}")
    os._exit(1)

for message in consumer:
    batch_str = message.value

    df_raw, metadata = preprocess_batch(batch_str)
    if df_raw is None:
        print("Skipping batch — preprocessing failed")
        continue

    if SOURCE_TYPE == "website":
        df_features = extract_website_features(df_raw)
        if df_features is None:
            print("Skipping batch — website feature extraction failed")
            continue
        metadata = metadata.loc[df_features.index].reset_index(drop=True)
        results = predict_website(df_features, metadata)
    else:
        df_features = extract_iot_features(df_raw)
        if df_features is None:
            print("Skipping batch — IoT feature extraction failed")
            continue
        metadata = metadata.loc[df_features.index].reset_index(drop=True)
        results = predict_iot(df_features, metadata)

    num_results = len(results)
    num_alerts = sum(1 for r in results if r["is_alert"])

    metrics["flows_processed"] += num_results
    metrics["alerts_triggered"] += num_alerts
    add_to_history(num_results, num_alerts)
    metrics["last_batch_time"] = datetime.now(timezone.utc).isoformat()

    alerts = [r for r in results if r["is_alert"]]
    benign = [r for r in results if not r["is_alert"]]
    print(f"\n[BATCH] Flows: {len(results)} | Benign: {len(benign)} | Alerts: {len(alerts)} | Model: {SOURCE_TYPE}")

    if alerts:
        print("ALERTS:")
        for alert in alerts:
            print(f"  → {alert['prediction']} "
                  f"(confidence: {alert['confidence']*100:.1f}%) "
                  f"| {alert['severity']} "
                  f"| {alert['src_ip']} → {alert['dst_ip']}")
    else:
        print("All flows benign")

    send_to_backend(results)