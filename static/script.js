let protocolChartInstance = null;
let threatChartInstance = null;
let globalLogData = []; 
let refreshInterval = null;

// --- TAB SWITCHING LOGIC ---
function switchTab(tabId, element) {
    document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById('view-' + tabId).classList.add('active');
    
    document.querySelectorAll('.nav-links li').forEach(li => {
        li.classList.remove('active');
    });
    element.classList.add('active');
}

// --- CSV EXPORT LOGIC ---
function exportToCSV() {
    if (globalLogData.length === 0) {
        alert("No data to export!");
        return;
    }
    let csvContent = "data:text/csv;charset=utf-8,ID,Timestamp,Source IP,Destination IP,Protocol,Length,Alert Type,App Payload\n";
    globalLogData.forEach(row => {
        // Enclose payload in quotes in case it contains commas
        let payload = row[7] ? `"${row[7].replace(/"/g, '""')}"` : '"-"';
        let formattedRow = [row[0], row[1], row[2], row[3], row[4], row[5], row[6], payload];
        csvContent += formattedRow.join(",") + "\n";
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "nids_soc_report_" + new Date().getTime() + ".csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// --- AUTO REFRESH TOGGLE ---
function toggleAutoRefresh() {
    const isChecked = document.getElementById('toggleRefresh').checked;
    if (isChecked) {
        refreshInterval = setInterval(loadLogs, 3000);
    } else {
        clearInterval(refreshInterval);
    }
}

// --- CORE DASHBOARD LOGIC ---
async function loadLogs() {
    try {
        const res = await fetch('/logs');
        const data = await res.json();
        globalLogData = data; 

        let stats = { tcp: 0, udp: 0, icmp: 0, other: 0, dns: 0, http: 0 };
        let threats = { 'PORT SCAN': 0, 'SENSITIVE PORT': 0, 'PING': 0 };
        let totalThreats = 0;
        let uniqueIPs = new Set(); 

        let tableHTML = "";

        data.forEach(row => {
            const id = row[0];
            const time = new Date(row[1]).toLocaleTimeString();
            const srcIP = row[2];
            const dstIP = row[3];
            const protocol = row[4];
            const length = row[5];
            const alert = row[6];
            const appData = row[7] || "-";

            if(srcIP !== "Unknown") uniqueIPs.add(srcIP);
            if(dstIP !== "Unknown") uniqueIPs.add(dstIP);

            // Updated Analytics for DPI
            if (protocol === "TCP") stats.tcp++;
            else if (protocol === "UDP") stats.udp++;
            else if (protocol === "ICMP") stats.icmp++;
            else if (protocol === "DNS") stats.dns++;
            else if (protocol === "HTTP") stats.http++;
            else stats.other++;

            let badgeClass = "normal";
            let displayAlert = alert;

            if (alert.includes("PORT SCAN")) {
                badgeClass = "danger"; totalThreats++; threats['PORT SCAN']++;
            } else if (alert.includes("SENSITIVE")) {
                badgeClass = "warning"; totalThreats++; threats['SENSITIVE PORT']++;
            } else if (alert.includes("PING")) {
                badgeClass = "warning"; threats['PING']++;
            }

            tableHTML += `
                <tr>
                    <td>#${id}</td>
                    <td style="color:#9ca3af">${time}</td>
                    <td style="font-weight:bold; color:#3b82f6">${protocol} <span style="font-size:0.7rem; color:#6b7280">(${length}B)</span></td>
                    <td><a href="/ip/${srcIP}" target="_blank">${srcIP}</a></td>
                    <td><a href="/ip/${dstIP}" target="_blank">${dstIP}</a></td>
                    <td style="color:#9ca3af; font-size:0.85rem; max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${appData}">${appData}</td>
                    <td><span class="badge ${badgeClass}">${displayAlert}</span></td>
                </tr>
            `;
        });

        document.getElementById("logs").innerHTML = tableHTML;

        // Update KPIs
        document.getElementById("kpi-total").innerText = data.length;
        document.getElementById("kpi-threats").innerText = totalThreats;
        document.getElementById("kpi-scans").innerText = threats['PORT SCAN'] || 0;

        // Update Network Map IP List
        const ipListElement = document.getElementById('unique-ips-list');
        if(uniqueIPs.size === 0) {
            ipListElement.innerHTML = "<li>No active connections.</li>";
        } else {
            let ipHTML = "";
            uniqueIPs.forEach(ip => {
                ipHTML += `<li><i class="fa-solid fa-server" style="color:#3b82f6; margin-right:8px;"></i> ${ip}</li>`;
            });
            ipListElement.innerHTML = ipHTML;
        }

        updateCharts(stats, threats);

    } catch (err) {
        console.error("Failed to fetch logs:", err);
    }
}

// --- CHART RENDERING ---
function updateCharts(stats, threats) {
    const ctxProto = document.getElementById('protocolChart').getContext('2d');
    if (protocolChartInstance) protocolChartInstance.destroy();
    
    // Updated chart to include DPI protocols
    protocolChartInstance = new Chart(ctxProto, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'Other'],
            datasets: [{
                data: [stats.tcp, stats.udp, stats.icmp, stats.dns, stats.http, stats.other],
                backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#6b7280'],
                borderWidth: 0
            }]
        },
        options: { 
            responsive: true, 
            maintainAspectRatio: false, 
            animation: false, 
            layout: {
                padding: { bottom: 10 }
            },
            plugins: { 
                legend: { 
                    position: 'bottom',
                    labels: { 
                        color: '#f3f4f6',
                        padding: 15
                    } 
                } 
            } 
        }
    });

    const ctxThreat = document.getElementById('threatChart').getContext('2d');
    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctxThreat, {
        type: 'bar',
        data: {
            labels: ['Port Scans', 'Sensitive Ports', 'Ping Sweeps'],
            datasets: [{
                label: 'Threat Count',
                data: [threats['PORT SCAN'] || 0, threats['SENSITIVE PORT'] || 0, threats['PING'] || 0],
                backgroundColor: '#ef4444',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            scales: {
                y: { beginAtZero: true, grid: { color: '#1f2937' }, ticks: { color: '#9ca3af', stepSize: 1 } },
                x: { grid: { display: false }, ticks: { color: '#9ca3af' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// --- SEARCH FILTER ---
function filterLogs() {
    let input = document.getElementById("searchInput").value.toUpperCase();
    let table = document.getElementById("logTable");
    let tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let match = false;
        let tds = tr[i].getElementsByTagName("td");
        for (let j = 0; j < tds.length; j++) {
            if (tds[j]) {
                if (tds[j].innerHTML.toUpperCase().indexOf(input) > -1) {
                    match = true; break;
                }
            }
        }
        tr[i].style.display = match ? "" : "none";
    }
}

refreshInterval = setInterval(loadLogs, 3000);
loadLogs();