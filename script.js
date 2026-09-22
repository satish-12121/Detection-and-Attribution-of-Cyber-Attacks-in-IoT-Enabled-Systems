let monitoring = false;

let attackCount = 2;

let risk = 38;


/* Start Monitoring */

function startMonitoring() {

    monitoring = true;

    document.getElementById("securityMessage").innerText =
        "Real-time monitoring is active. Analyzing IoT network traffic...";

    document.getElementById("statusBadge").innerText =
        "MONITORING";

    document.getElementById("statusBadge").className =
        "status-safe";

    addLog(
        "System",
        "Real-time monitoring started",
        "System",
        "Low"
    );

}


/* Simulate Cyber Attack */

function simulateAttack() {

    monitoring = true;

    attackCount++;

    risk += 15;

    if (risk > 100) {
        risk = 100;
    }


    document.getElementById("attackCount").innerText =
        attackCount;


    document.getElementById("riskScore").innerText =
        risk + "%";


    document.getElementById("riskText").innerText =
        risk + "%";


    document.getElementById("riskBar").style.width =
        risk + "%";


    document.getElementById("riskBar").style.background =
        "#ef4444";


    document.getElementById("statusBadge").innerText =
        "ATTACK DETECTED";


    document.getElementById("statusBadge").className =
        "status-danger";


    document.getElementById("securityMessage").innerText =
        "Suspicious network behaviour detected! Investigation required.";


    /* Random Attack */

    const attacks = [

        {
            type: "DDoS Attack",
            method: "Traffic Anomaly Detection",
            confidence: "96%",
            ip: "10.0.0.45",
            device: "IoT-004 Smart Router",
            level: "Critical"
        },

        {
            type: "Brute Force Attack",
            method: "Authentication Behaviour Analysis",
            confidence: "91%",
            ip: "172.16.0.25",
            device: "IoT-003 Smart Door Lock",
            level: "High"
        },

        {
            type: "Port Scanning",
            method: "Network Traffic Analysis",
            confidence: "88%",
            ip: "192.168.1.200",
            device: "IoT-002 Temperature Sensor",
            level: "Medium"
        },

        {
            type: "Malware Activity",
            method: "Behavioural Anomaly Detection",
            confidence: "94%",
            ip: "10.10.10.15",
            device: "IoT-006 Smart Camera",
            level: "Critical"
        }

    ];


    const attack =
        attacks[
            Math.floor(
                Math.random() * attacks.length
            )
        ];


    document.getElementById("attackType").innerText =
        attack.type;


    document.getElementById("detectionMethod").innerText =
        attack.method;


    document.getElementById("confidence").innerText =
        attack.confidence;


    document.getElementById("sourceIP").innerText =
        attack.ip;


    document.getElementById("sourceDevice").innerText =
        attack.device;


    document.getElementById("threatLevel").innerText =
        attack.level;


    addLog(
        attack.device,
        attack.type + " detected",
        attack.ip,
        attack.level
    );

}


/* Add Security Log */

function addLog(
    device,
    event,
    ip,
    severity
) {

    const table =
        document.getElementById("logTable");


    const row =
        document.createElement("tr");


    const currentTime =
        new Date().toLocaleTimeString();


    let severityClass = "normal";


    if (severity === "Medium") {

        severityClass = "warning";

    }


    if (
        severity === "High" ||
        severity === "Critical"
    ) {

        severityClass = "danger";

    }


    row.innerHTML = `

        <td>${currentTime}</td>

        <td>${device}</td>

        <td>${event}</td>

        <td>${ip}</td>

        <td>
            <span class="${severityClass}">
                ${severity}
            </span>
        </td>

    `;


    table.prepend(row);

}


/* Automatic Monitoring */

setInterval(function () {

    if (!monitoring) {
        return;
    }


    const random =
        Math.random();


    if (random > 0.75) {

        simulateAttack();

    }

}, 8000);
