import os
import joblib


MODEL_PATH = "models/model.pkl"


def load_model():

    if os.path.exists(MODEL_PATH):

        try:

            return joblib.load(MODEL_PATH)

        except Exception:

            return None

    return None


model = load_model()


def calculate_risk(
    packets,
    packet_rate,
    connections,
    failed_logins,
    bytes_transferred
):

    risk = 0


    # Extremely high packet count
    if packets > 5000:

        risk += 25

    elif packets > 2000:

        risk += 15


    # High packet rate
    if packet_rate > 500:

        risk += 25

    elif packet_rate > 200:

        risk += 15


    # Large number of connections
    if connections > 100:

        risk += 20

    elif connections > 50:

        risk += 10


    # Failed authentication attempts
    if failed_logins > 30:

        risk += 25

    elif failed_logins > 10:

        risk += 15


    # Large data transfer
    if bytes_transferred > 50000000:

        risk += 10


    return min(risk, 100)


def classify_attack(
    packets,
    packet_rate,
    connections,
    failed_logins,
    bytes_transferred
):

    # DDoS / flooding behaviour
    if packet_rate > 500 and packets > 5000:

        return (
            "DDoS Attack",
            95,
            "Traffic Anomaly Detection"
        )


    # Brute-force behaviour
    if failed_logins > 30:

        return (
            "Brute Force Attack",
            93,
            "Authentication Behaviour Analysis"
        )


    # Port scanning / reconnaissance
    if connections > 100 and packet_rate > 200:

        return (
            "Port Scanning",
            89,
            "Network Traffic Analysis"
        )


    # Suspicious large transfer
    if bytes_transferred > 50000000:

        return (
            "Possible Malware Activity",
            86,
            "Behavioural Anomaly Detection"
        )


    # Mild suspicious traffic
    if packet_rate > 200 or connections > 50:

        return (
            "Suspicious Activity",
            72,
            "Anomaly Detection"
        )


    return (
        "Normal Traffic",
        98,
        "Normal Behaviour Analysis"
    )


def detect_attack(data):

    packets = int(
        data.get("packets", 0)
    )

    packet_rate = float(
        data.get("packet_rate", 0)
    )

    connections = int(
        data.get("connections", 0)
    )

    failed_logins = int(
        data.get("failed_logins", 0)
    )

    bytes_transferred = int(
        data.get("bytes_transferred", 0)
    )


    risk_score = calculate_risk(
        packets,
        packet_rate,
        connections,
        failed_logins,
        bytes_transferred
    )


    attack_type, confidence, method = classify_attack(
        packets,
        packet_rate,
        connections,
        failed_logins,
        bytes_transferred
    )


    # Risk classification

    if risk_score >= 80:

        risk_level = "Critical"

    elif risk_score >= 60:

        risk_level = "High"

    elif risk_score >= 30:

        risk_level = "Medium"

    else:

        risk_level = "Low"


    is_attack = attack_type != "Normal Traffic"


    return {

        "is_attack": is_attack,

        "attack_type": attack_type,

        "confidence": confidence,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "detection_method": method

    }


def attribute_attack(data, detection):

    source_ip = data.get(
        "source_ip",
        "Unknown"
    )

    device_id = data.get(
        "device_id",
        "Unknown"
    )


    if not detection["is_attack"]:

        return {

            "source_ip": source_ip,

            "source_device": device_id,

            "attribution_status": "No malicious source identified"

        }


    # Basic attribution based on observed source
    return {

        "source_ip": source_ip,

        "source_device": device_id,

        "attribution_status":
            "Potential source identified from network traffic"

    }
