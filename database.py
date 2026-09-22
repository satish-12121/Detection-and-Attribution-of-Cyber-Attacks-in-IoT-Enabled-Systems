import sqlite3
from datetime import datetime


DATABASE = "iot_security.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    # IoT devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT UNIQUE NOT NULL,

            device_name TEXT NOT NULL,

            device_type TEXT,

            ip_address TEXT,

            status TEXT DEFAULT 'Online',

            created_at TEXT

        )
    """)


    # Security events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            attack_type TEXT,

            confidence REAL,

            risk_score INTEGER,

            risk_level TEXT,

            detection_method TEXT,

            timestamp TEXT

        )
    """)


    # Network traffic table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_traffic (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            packets INTEGER,

            packet_rate REAL,

            connections INTEGER,

            failed_logins INTEGER,

            bytes_transferred INTEGER,

            timestamp TEXT

        )
    """)


    connection.commit()

    connection.close()


def add_device(
    device_id,
    device_name,
    device_type,
    ip_address
):

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute("""
            INSERT INTO devices
            (
                device_id,
                device_name,
                device_type,
                ip_address,
                status,
                created_at
            )

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            device_name,
            device_type,
            ip_address,
            "Online",
            datetime.now().isoformat()
        ))

        connection.commit()

        result = True

    except sqlite3.IntegrityError:

        result = False

    connection.close()

    return result


def get_devices():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM devices
        ORDER BY id DESC
    """)

    devices = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return devices


def add_security_event(data):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (
            device_id,
            source_ip,
            destination_ip,
            attack_type,
            confidence,
            risk_score,
            risk_level,
            detection_method,
            timestamp
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["device_id"],
        data["source_ip"],
        data["destination_ip"],
        data["attack_type"],
        data["confidence"],
        data["risk_score"],
        data["risk_level"],
        data["detection_method"],
        datetime.now().isoformat()
    ))

    connection.commit()

    connection.close()


def add_network_traffic(data):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO network_traffic
        (
            device_id,
            source_ip,
            destination_ip,
            packets,
            packet_rate,
            connections,
            failed_logins,
            bytes_transferred,
            timestamp
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["device_id"],
        data["source_ip"],
        data["destination_ip"],
        data["packets"],
        data["packet_rate"],
        data["connections"],
        data["failed_logins"],
        data["bytes_transferred"],
        datetime.now().isoformat()
    ))

    connection.commit()

    connection.close()


def get_security_events(limit=50):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    events = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return events


def get_statistics():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM devices
    """)

    total_devices = cursor.fetchone()["total"]


    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_events
    """)

    total_attacks = cursor.fetchone()["total"]


    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_level IN ('High', 'Critical')
    """)

    high_risk = cursor.fetchone()[0]


    cursor.execute("""
        SELECT AVG(risk_score)
        FROM security_events
    """)

    average_risk = cursor.fetchone()[0]


    if average_risk is None:

        average_risk = 0


    connection.close()


    return {

        "total_devices": total_devices,

        "total_attacks": total_attacks,

        "high_risk_events": high_risk,

        "average_risk": round(
            average_risk,
            2
        )

    }
