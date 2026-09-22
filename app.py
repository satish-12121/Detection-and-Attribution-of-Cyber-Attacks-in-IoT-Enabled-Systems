from flask import (
    Flask,
    request,
    jsonify
)

from flask_cors import CORS

from database import (
    initialize_database,
    add_device,
    get_devices,
    add_security_event,
    add_network_traffic,
    get_security_events,
    get_statistics
)

from detector import (
    detect_attack,
    attribute_attack
)


app = Flask(__name__)

CORS(app)


# Initialize database
initialize_database()


# ------------------------------------------------
# HOME
# ------------------------------------------------

@app.route("/")
def home():

    return jsonify({

        "application":
            "IoT Cyber Attack Detection and Attribution System",

        "status":
            "Backend is running",

        "version":
            "1.0",

        "message":
            "IoT security API is active"

    })


# ------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({

        "status": "healthy",

        "service":
            "IoT Security Backend"

    })


# ------------------------------------------------
# ADD DEVICE
# ------------------------------------------------

@app.route(
    "/api/devices",
    methods=["POST"]
)
def register_device():

    data = request.get_json()


    required_fields = [
        "device_id",
        "device_name",
        "device_type",
        "ip_address"
    ]


    for field in required_fields:

        if field not in data:

            return jsonify({

                "success": False,

                "error":
                    f"Missing field: {field}"

            }), 400


    result = add_device(

        data["device_id"],

        data["device_name"],

        data["device_type"],

        data["ip_address"]

    )


    if not result:

        return jsonify({

            "success": False,

            "error":
                "Device already exists"

        }), 409


    return jsonify({

        "success": True,

        "message":
            "IoT device registered successfully"

    }), 201


# ------------------------------------------------
# GET DEVICES
# ------------------------------------------------

@app.route(
    "/api/devices",
    methods=["GET"]
)
def devices():

    return jsonify({

        "success": True,

        "devices":
            get_devices()

    })


# ------------------------------------------------
# ANALYZE NETWORK TRAFFIC
# ------------------------------------------------

@app.route(
    "/api/detect",
    methods=["POST"]
)
def detect():

    data = request.get_json()


    required_fields = [

        "device_id",

        "source_ip",

        "destination_ip",

        "packets",

        "packet_rate",

        "connections",

        "failed_logins",

        "bytes_transferred"

    ]


    for field in required_fields:

        if field not in data:

            return jsonify({

                "success": False,

                "error":
                    f"Missing field: {field}"

            }), 400


    # Save raw traffic
    add_network_traffic(data)


    # Run detection engine
    detection = detect_attack(data)


    # Attribution
    attribution = attribute_attack(
        data,
        detection
    )


    # Save security event only
    # when suspicious activity is found

    if detection["is_attack"]:

        event = {

            "device_id":
                data["device_id"],

            "source_ip":
                data["source_ip"],

            "destination_ip":
                data["destination_ip"],

            "attack_type":
                detection["attack_type"],

            "confidence":
                detection["confidence"],

            "risk_score":
                detection["risk_score"],

            "risk_level":
                detection["risk_level"],

            "detection_method":
                detection["detection_method"]

        }


        add_security_event(event)


    return jsonify({

        "success": True,

        "detection": detection,

        "attribution": attribution,

        "traffic": {

            "device_id":
                data["device_id"],

            "source_ip":
                data["source_ip"],

            "destination_ip":
                data["destination_ip"]

        }

    })


# ------------------------------------------------
# SECURITY LOGS
# ------------------------------------------------

@app.route(
    "/api/logs",
    methods=["GET"]
)
def logs():

    limit = request.args.get(
        "limit",
        default=50,
        type=int
    )


    return jsonify({

        "success": True,

        "logs":
            get_security_events(limit)

    })


# ------------------------------------------------
# DASHBOARD STATISTICS
# ------------------------------------------------

@app.route(
    "/api/statistics",
    methods=["GET"]
)
def statistics():

    return jsonify({

        "success": True,

        "statistics":
            get_statistics()

    })


# ------------------------------------------------
# SIMULATE ATTACK
# ------------------------------------------------

@app.route(
    "/api/simulate-attack",
    methods=["GET"]
)
def simulate_attack():

    test_data = {

        "device_id":
            "IoT-004",

        "source_ip":
            "10.0.0.45",

        "destination_ip":
            "192.168.1.104",

        "packets":
            8500,

        "packet_rate":
            950,

        "connections":
            120,

        "failed_logins":
            5,

        "bytes_transferred":
            12000000

    }


    detection = detect_attack(
        test_data
    )


    attribution = attribute_attack(
        test_data,
        detection
    )


    event = {

        "device_id":
            test_data["device_id"],

        "source_ip":
            test_data["source_ip"],

        "destination_ip":
            test_data["destination_ip"],

        "attack_type":
            detection["attack_type"],

        "confidence":
            detection["confidence"],

        "risk_score":
            detection["risk_score"],

        "risk_level":
            detection["risk_level"],

        "detection_method":
            detection["detection_method"]

    }


    add_security_event(event)


    return jsonify({

        "success": True,

        "message":
            "Simulated attack processed",

        "detection":
            detection,

        "attribution":
            attribution

    })


# ------------------------------------------------
# ERROR HANDLER
# ------------------------------------------------

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "success": False,

        "error":
            "API endpoint not found"

    }), 404


# ------------------------------------------------
# RUN SERVER
# ------------------------------------------------

if __name__ == "__main__":

    print(
        "\n=========================================="
    )

    print(
        " IoT Cyber Attack Detection Backend"
    )

    print(
        "=========================================="
    )

    print(
        "Server: http://127.0.0.1:5000"
    )

    print(
        "API:    http://127.0.0.1:5000/api/health"
    )

    print(
        "==========================================\n"
    )


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )
