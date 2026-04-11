/*
   dashboard.js
   Author: Gokul (copied for integration)
   Purpose: Javascript logic
*/

let severityChart = null;
let ipChart = null;

let allAlertsData = [];


function showStatus(message, isError = false) {
    const bar = document.getElementById("status-bar");
    const msg = document.getElementById("status-message");
    bar.classList.remove("hidden");
    msg.textContent = message;
    bar.style.borderColor = isError ? "#f85149" : "#58a6ff";
    msg.style.color = isError ? "#f85149" : "#58a6ff";
}

function hideStatus() {
    document.getElementById("status-bar").classList.add("hidden");
}

function updateTimestamp() {
    const now = new Date().toLocaleTimeString();
    document.getElementById("last-updated").textContent = `Last updated: ${now}`;
}

function getSeverityColor(severity) {
    const colors = {
        "CRITICAL": "#f85149",
        "HIGH":     "#e3b341",
        "MEDIUM":   "#d29922",
        "LOW":      "#3fb950"
    };
    return colors[severity] || "#8b949e";
}



function updateSummaryCards(severityCounts, total) {
    document.getElementById("total-count").textContent    = total || 0;
    document.getElementById("critical-count").textContent = severityCounts["CRITICAL"] || 0;
    document.getElementById("high-count").textContent     = severityCounts["HIGH"] || 0;
    document.getElementById("medium-count").textContent   = severityCounts["MEDIUM"] || 0;
    document.getElementById("low-count").textContent      = severityCounts["LOW"] || 0;
}



function updateSeverityChart(severityCounts) {
    const ctx = document.getElementById("severity-chart").getContext("2d");

    const labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const data   = labels.map(l => severityCounts[l] || 0);
    const colors = labels.map(l => getSeverityColor(l));

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: "#161b22",
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#c9d1d9", padding: 16 }
                }
            }
        }
    });
}


function updateIPChart(topIPs) {
    const ctx = document.getElementById("ip-chart").getContext("2d");

    const labels = topIPs.map(item => item.source_ip);
    const data   = topIPs.map(item => item.count);

    if (ipChart) {
        ipChart.destroy();
    }

    ipChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Alert Count",
                data: data,
                backgroundColor: "#58a6ff",
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    ticks: { color: "#8b949e", font: { size: 11 } },
                    grid:  { color: "#21262d" }
                },
                y: {
                    ticks: { color: "#8b949e" },
                    grid:  { color: "#21262d" },
                    beginAtZero: true
                }
            }
        }
    });
}



function renderAlertsTable(alerts) {
    const tbody = document.getElementById("alerts-body");
    tbody.innerHTML = "";

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-msg">No alerts found</td></tr>`;
        return;
    }

    alerts.forEach(alert => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><span class="badge badge-${alert.severity}">${alert.severity}</span></td>
            <td>${alert.score}</td>
            <td>${alert.event_type}</td>
            <td>${alert.source_ip}</td>
            <td>${alert.timestamp}</td>
            <td>${alert.log_source}</td>
            <td class="raw-log" title="${alert.raw_log}">${alert.raw_log}</td>
        `;
        tbody.appendChild(row);
    });
}



function renderBlacklistTable(ips) {
    const tbody = document.getElementById("blacklist-body");
    tbody.innerHTML = "";

    if (ips.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-msg">No blacklisted IPs yet</td></tr>`;
        return;
    }

    ips.forEach(ip => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td style="color: #f85149; font-weight: 600;">${ip.ip_address}</td>
            <td>${ip.reason}</td>
            <td>${ip.flagged_at}</td>
        `;
        tbody.appendChild(row);
    });
}



async function fetchAlerts(severity = null) {
    try {
        let url = "/api/alerts";
        if (severity && severity !== "ALL") {
            url += `?severity=${severity}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        allAlertsData = data.alerts;
        renderAlertsTable(data.alerts);

    } catch (error) {
        showStatus("Error fetching alerts: " + error.message, true);
    }
}


async function fetchStats() {
    try {
        const response = await fetch("/api/stats");
        const data = await response.json();

        updateSummaryCards(data.severity_counts, data.total_alerts);
        updateSeverityChart(data.severity_counts);
        updateIPChart(data.top_ips);

    } catch (error) {
        showStatus("Error fetching stats: " + error.message, true);
    }
}


async function fetchBlacklist() {
    try {
        const response = await fetch("/api/blacklist");
        const data = await response.json();
        renderBlacklistTable(data.blacklisted_ips);
    } catch (error) {
        console.error("Error fetching blacklist:", error);
    }
}


async function refreshDashboard() {
    showStatus("Refreshing dashboard...");
    await fetchAlerts();
    await fetchStats();
    await fetchBlacklist();
    updateTimestamp();
    hideStatus();
}


document.getElementById("btn-analyse").addEventListener("click", async () => {
    showStatus("Running analysis on log files...");

    try {
        const response = await fetch("/api/process", { method: "POST" });
        const data = await response.json();

        showStatus(data.message);

        await refreshDashboard();

        setTimeout(hideStatus, 3000);

    } catch (error) {
        showStatus("Error running analysis: " + error.message, true);
    }
});


document.getElementById("btn-refresh").addEventListener("click", async () => {
    await refreshDashboard();
});


document.getElementById("btn-clear").addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear all alerts?")) return;

    try {
        await fetch("/api/clear", { method: "POST" });
        showStatus("All alerts cleared.");
        await refreshDashboard();
        setTimeout(hideStatus, 2000);
    } catch (error) {
        showStatus("Error clearing alerts: " + error.message, true);
    }
});


document.getElementById("btn-upload").addEventListener("click", async () => {
    const fileInput = document.getElementById("file-upload");
    const logType   = document.getElementById("log-type-select").value;

    if (!fileInput.files.length) {
        showStatus("Please select a file first.", true);
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("log_type", logType);

    showStatus("Uploading and processing file...");

    try {
        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });
        const data = await response.json();
        showStatus(data.message);
        await refreshDashboard();
        setTimeout(hideStatus, 3000);
    } catch (error) {
        showStatus("Upload error: " + error.message, true);
    }
});


document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        const severity = btn.getAttribute("data-severity");
        fetchAlerts(severity);
    });
});


document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();
});