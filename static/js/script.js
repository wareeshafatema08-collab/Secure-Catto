
const scanForm = document.getElementById("scanForm");
const websiteUrl = document.getElementById("websiteUrl");
const scanButton = document.getElementById("scanButton");
const scanMessage = document.getElementById("scanMessage");

let securityChart = null;


// MESSAGE HANDLING

function showMessage(message, isError = false) {
    scanMessage.textContent = message;
    scanMessage.style.color = isError ? "#ff647c" : "#38d9ef";
}

function getRiskClass(risk) {
    return String(risk).toLowerCase();
}


// DASHBOARD

function updateDashboard(result) {
    document.getElementById("securityScore").innerHTML =
        `${result.security_score}<small>/100</small>`;

    const riskElement = document.getElementById("riskLevel");

    riskElement.textContent = result.risk_level;
    riskElement.className =
        "stat-value risk-" + getRiskClass(result.risk_level);

    document.getElementById("lastScan").textContent =
        result.scan_time;

    displayResults(result);
    displayRecommendations(result.recommendations);
    updateChart(result.security_score);
}


// SCAN RESULTS

function displayResults(result) {
    const container = document.getElementById("scanResults");

    container.replaceChildren();

    const details = [
        ["Website", result.url],
        ["HTTP Status", result.status_code],
        ["HTTPS Enabled", result.https ? "Yes" : "No"],
        ["TLS Version", result.tls_version],
        ["Certificate Expiry", result.certificate_expiry],
        ["Security Score", `${result.security_score}/100`],
        ["Risk Level", result.risk_level]
    ];

    details.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "result-item";

        const heading = document.createElement("strong");
        heading.textContent = label;

        const paragraph = document.createElement("p");
        paragraph.textContent = value ?? "Unavailable";

        item.append(heading, paragraph);
        container.appendChild(item);
    });

    const headerItem = document.createElement("div");
    headerItem.className = "result-item";

    const headerTitle = document.createElement("strong");
    headerTitle.textContent = "Security Headers";

    headerItem.appendChild(headerTitle);

    const headers = result.headers || {};
    const headerNames = Object.keys(headers);

    if (headerNames.length === 0) {
        const paragraph = document.createElement("p");
        paragraph.textContent =
            "Security header details were not included in this scan.";

        headerItem.appendChild(paragraph);
    } else {
        Object.entries(headers).forEach(([name, details]) => {
            const paragraph = document.createElement("p");

            paragraph.textContent =
                `${name}: ${details.present ? "Present" : "Missing"}`;

            headerItem.appendChild(paragraph);
        });
    }

    container.appendChild(headerItem);

    const cookieItem = document.createElement("div");
    cookieItem.className = "result-item";

    const cookieTitle = document.createElement("strong");
    cookieTitle.textContent = "Cookie Security";

    cookieItem.appendChild(cookieTitle);

    const cookies = result.cookies || [];

    if (cookies.length === 0) {
        const paragraph = document.createElement("p");

        paragraph.textContent =
            "No cookie details were included in this scan.";

        cookieItem.appendChild(paragraph);
    } else {
        cookies.forEach(cookie => {
            const paragraph = document.createElement("p");

            paragraph.textContent =
                `${cookie.name}: Secure=${cookie.secure}, ` +
                `HttpOnly=${cookie.httponly}, ` +
                `SameSite=${cookie.samesite}`;

            cookieItem.appendChild(paragraph);
        });
    }

    container.appendChild(cookieItem);
}


// RECOMMENDATIONS

function displayRecommendations(recommendations) {
    const container = document.getElementById("recommendations");

    container.replaceChildren();

    recommendations.forEach(recommendation => {
        const item = document.createElement("div");
        item.className = "recommendation-item";

        const icon = document.createElement("span");
        icon.textContent = "✦";

        const text = document.createElement("p");
        text.textContent = recommendation;

        item.append(icon, text);
        container.appendChild(item);
    });
}


// SECURITY CHART

function updateChart(score) {
    if (typeof Chart === "undefined") {
        return;
    }

    const canvas = document.getElementById("securityChart");
    const context = canvas.getContext("2d");

    if (securityChart) {
        securityChart.destroy();
    }

    securityChart = new Chart(context, {
        type: "doughnut",

        data: {
            labels: ["Security Score", "Remaining"],

            datasets: [{
                data: [score, 100 - score],
                backgroundColor: ["#925cff", "#252b40"],
                borderWidth: 0,
                hoverOffset: 5
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "76%",

            plugins: {
                legend: {
                    position: "bottom",

                    labels: {
                        color: "#aab1c6",
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}


// SCAN HISTORY

async function loadHistory() {
    const table = document.getElementById("historyTable");

    try {
        const response = await fetch("/history");

        if (!response.ok) {
            throw new Error("Could not load scan history.");
        }

        const history = await response.json();

        document.getElementById("totalScans").textContent =
            history.length;

        table.replaceChildren();

        if (history.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 4;
            cell.className = "table-empty";
            cell.textContent = "No scan history available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        history.forEach(scan => {
            const row = document.createElement("tr");

            const values = [
                scan.url,
                `${scan.score}/100`,
                scan.risk,
                scan.scan_time
            ];

            values.forEach((value, index) => {
                const cell = document.createElement("td");

                cell.textContent = value;

                if (index === 2) {
                    cell.className =
                        "risk-" + getRiskClass(scan.risk);
                }

                row.appendChild(cell);
            });

            table.appendChild(row);
        });

        if (history.length > 0) {
            document.getElementById("lastScan").textContent =
                history[0].scan_time;
        }

    } catch (error) {
        showMessage(error.message, true);
    }
}


// REPORTS

async function loadReports() {
    const table = document.getElementById("reportsTable");

    table.replaceChildren();

    try {
        const response = await fetch("/reports");

        if (!response.ok) {
            throw new Error("Could not load reports.");
        }

        const data = await response.json();

        const reports = Array.isArray(data)
            ? data
            : (data.reports || []);

        if (reports.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.className = "table-empty";
            cell.textContent = "No reports available.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        reports.forEach(report => {
            const row = document.createElement("tr");

            const values = [
                report.url,
                `${report.score}/100`,
                report.risk,
                report.scan_time
            ];

            values.forEach((value, index) => {
                const cell = document.createElement("td");

                cell.textContent = value ?? "Unavailable";

                if (index === 2) {
                    cell.className =
                        "risk-" + getRiskClass(report.risk);
                }

                row.appendChild(cell);
            });

            const reportCell = document.createElement("td");
            const downloadButton = document.createElement("button");

            downloadButton.type = "button";
            downloadButton.className = "text-button";
            downloadButton.textContent = "Download PDF ↓";

            downloadButton.addEventListener("click", () => {
                window.location.href =
                    `/reports/${encodeURIComponent(report.id)}/pdf`;
            });

            reportCell.appendChild(downloadButton);
            row.appendChild(reportCell);

            table.appendChild(row);
        });

    } catch (error) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.className = "table-empty";
        cell.textContent = error.message;

        row.appendChild(cell);
        table.appendChild(row);
    }
}


// SETTINGS

async function loadSettings() {
    const message = document.getElementById("settingsMessage");

    try {
        const response = await fetch("/settings");

        if (!response.ok) {
            throw new Error("Could not load settings.");
        }

        const settings = await response.json();

        document.getElementById("scanTimeout").value =
            settings.scan_timeout ?? 10;

        document.getElementById("followRedirects").checked =
            Boolean(settings.follow_redirects);

        document.getElementById("includeHeaders").checked =
            settings.include_headers !== false;

        document.getElementById("includeCookies").checked =
            settings.include_cookies !== false;

        document.getElementById("saveHistory").checked =
            settings.save_history !== false;

        message.textContent = "";

    } catch (error) {
        message.textContent = error.message;
        message.style.color = "#ff647c";
    }
}


// SAVE SETTINGS

document.getElementById("settingsForm")
    .addEventListener("submit", async function(event) {

        event.preventDefault();

        const message =
            document.getElementById("settingsMessage");

        const settings = {
            scan_timeout: Number(
                document.getElementById("scanTimeout").value
            ),

            follow_redirects:
                document.getElementById("followRedirects").checked,

            include_headers:
                document.getElementById("includeHeaders").checked,

            include_cookies:
                document.getElementById("includeCookies").checked,

            save_history:
                document.getElementById("saveHistory").checked
        };

        if (
            !Number.isInteger(settings.scan_timeout) ||
            settings.scan_timeout < 5 ||
            settings.scan_timeout > 30
        ) {
            message.textContent =
                "Scan timeout must be between 5 and 30 seconds.";

            message.style.color = "#ff647c";
            return;
        }

        try {
            const response = await fetch("/settings", {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(settings)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || "Could not save settings.");
            }

            message.textContent =
                "Settings saved successfully!";

            message.style.color = "#38d9ef";

        } catch (error) {
            message.textContent = error.message;
            message.style.color = "#ff647c";
        }
    });


// CLEAR HISTORY

document.getElementById("clearHistoryButton")
    .addEventListener("click", async function() {

        const confirmed = confirm(
            "Are you sure you want to permanently delete all scan history?"
        );

        if (!confirmed) {
            return;
        }

        try {
            const response = await fetch("/clear-history", {
                method: "POST"
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || "Could not clear history.");
            }

            await loadHistory();
            await loadReports();

            document.getElementById("securityScore").innerHTML =
                '--<small>/100</small>';

            document.getElementById("riskLevel").textContent = "--";
            document.getElementById("lastScan").textContent = "Never";

            document.getElementById("scanResults").innerHTML =
                '<div class="empty-state">' +
                '<div class="empty-icon">⌕</div>' +
                '<h3>No scan results yet</h3>' +
                '<p>Start a new scan to see website security details here.</p>' +
                '</div>';

            document.getElementById("recommendations").innerHTML =
                '<div class="recommendation-empty">' +
                '<span>✦</span>' +
                '<p>Security recommendations will appear after your first scan.</p>' +
                '</div>';

            if (securityChart) {
                securityChart.destroy();
                securityChart = null;
            }

            alert("Scan history cleared successfully!");

        } catch (error) {
            alert(error.message);
        }
    });


// CSV EXPORT

document.getElementById("exportCsvButton")
    .addEventListener("click", function() {
        window.location.href = "/reports/export/csv";
    });


// REPORT REFRESH

document.getElementById("refreshReports")
    .addEventListener("click", loadReports);


// SIDEBAR NAVIGATION

const dashboardView = document.getElementById("dashboardView");

const reportsSection = document.getElementById("reportsSection");
const guideSection = document.getElementById("guideSection");
const settingsSection = document.getElementById("settingsSection");

function showSection(section) {

    dashboardView.hidden = true;
    reportsSection.hidden = true;
    guideSection.hidden = true;
    settingsSection.hidden = true;

    if (section === "dashboard" ||
        section === "new-scan" ||
        section === "history") {

        dashboardView.hidden = false;

        if (section === "dashboard") {
            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });
        }

        if (section === "new-scan") {
            document.getElementById("new-scan").scrollIntoView({
                behavior: "smooth"
            });

            websiteUrl.focus();
        }

        if (section === "history") {
            document.getElementById("history").scrollIntoView({
                behavior: "smooth"
            });
        }
    }

    if (section === "reports") {
        reportsSection.hidden = false;
        loadReports();
    }

    if (section === "guide") {
        guideSection.hidden = false;
    }

    if (section === "settings") {
        settingsSection.hidden = false;
        loadSettings();
    }
}


// UPDATE SIDEBAR ACTIVE ITEM

document.querySelectorAll(".nav-link").forEach(link => {

    link.addEventListener("click", function(event) {

        event.preventDefault();

        document.querySelectorAll(".nav-link").forEach(item => {
            item.classList.remove("active");
        });

        this.classList.add("active");

        showSection(this.dataset.section);

    });

});


// WEBSITE SCAN

scanForm.addEventListener("submit", async function(event) {

    event.preventDefault();

    const url = websiteUrl.value.trim();

    if (!url) {
        showMessage("Please enter a website URL.", true);
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    showMessage("Analyzing website security. Please wait...");

    try {
        const response = await fetch("/scan", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || "Scan failed.");
        }

        updateDashboard(result);

        await loadHistory();

        showMessage("Website scan completed successfully!");

    } catch (error) {
        showMessage(error.message, true);

    } finally {
        scanButton.disabled = false;
        scanButton.innerHTML = "<span>⌕</span> Start Scan";
    }
});


// REFRESH HISTORY

document.getElementById("refreshHistory")
    .addEventListener("click", loadHistory);


// INITIAL LOAD

loadHistory();
