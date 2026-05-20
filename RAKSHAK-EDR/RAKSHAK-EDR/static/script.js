/* =========================================================
   RAKSHAK-EDR :: script.js
   Enterprise SOC Build
========================================================= */

// ---------------- Clock ----------------
function updateClock() {
  const now = new Date();
  const time = now.toTimeString().slice(0, 8);

  const days = ["SUN","MON","TUE","WED","THU","FRI","SAT"];
  const mons = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];

  const date =
    `${days[now.getDay()]} ${now.getDate()} ${mons[now.getMonth()]} ${now.getFullYear()}`;

  document.getElementById("clock").textContent = time;
  document.getElementById("cdate").textContent = date;
}

setInterval(updateClock, 1000);
updateClock();


// ---------------- Terminal ----------------
const TERMINAL_MSGS = [
  ["SYS", "Scanning network interfaces...", ""],
  ["NET", "Packet capture active on all interfaces", "ok"],
  ["FW",  "Firewall rule update applied", "ok"],
  ["SCAN","Port scan detected - source flagged", "warn"],
  ["ARP", "ARP integrity check passed", "ok"],
  ["DNS", "DNS anomaly detected - monitoring", "warn"],
  ["AUTH","Failed login attempt detected", "err"],
  ["IPS", "Intrusion prevention rule triggered", "warn"],
  ["NET", "Outbound traffic spike - logging", "warn"],
  ["SYS", "CPU usage nominal", ""],
  ["SYS", "Threat intelligence sync complete", "ok"]
];

const terminal = document.getElementById("terminal");

function addTerminal(text = null, level = "") {
  let msg;

  if (text) {
    msg = ["SOC", text, level];
  } else {
    msg = TERMINAL_MSGS[Math.floor(Math.random() * TERMINAL_MSGS.length)];
  }

  const div = document.createElement("div");
  div.className = "tline";

  const cls =
    msg[2] === "ok" ? "t-ok" :
    msg[2] === "warn" ? "t-warn" :
    msg[2] === "err" ? "t-err" : "";

  div.innerHTML =
    `<span class="t-ts">[${msg[0]}]</span><span class="${cls}">${msg[1]}</span>`;

  terminal.appendChild(div);

  while (terminal.children.length > 40) {
    terminal.removeChild(terminal.firstChild);
  }

  terminal.scrollTop = terminal.scrollHeight;
}

setInterval(() => addTerminal(), 3000);


// ---------------- Pulse ----------------
const canvas = document.getElementById("pulseCanvas");
const ctx = canvas.getContext("2d");
const pulseData = new Array(60).fill(0);

function drawPulse() {
  const W = canvas.clientWidth;
  const H = 80;

  canvas.width = W;
  canvas.height = H;

  ctx.clearRect(0, 0, W, H);

  pulseData.push(Math.random() * 55 + 10 + (Math.random() < 0.18 ? 30 : 0));
  pulseData.shift();

  const step = W / (pulseData.length - 1);

  ctx.beginPath();
  pulseData.forEach((v, i) => {
    const x = i * step;
    const y = H - v;

    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });

  ctx.strokeStyle = "#00ff9d";
  ctx.lineWidth = 1.8;
  ctx.shadowBlur = 10;
  ctx.shadowColor = "#00ff9d";
  ctx.stroke();
  ctx.shadowBlur = 0;
}

setInterval(drawPulse, 200);
drawPulse();


// ---------------- Popup ----------------
const popupEl = document.getElementById("popupAlert");
let alertShown = false;

function showAlert(msg) {
  document.getElementById("popupMsg").textContent = msg;
  popupEl.style.display = "block";

  setTimeout(() => popupEl.classList.add("show"), 10);
}

function closeAlert() {
  popupEl.classList.remove("show");

  setTimeout(() => {
    popupEl.style.display = "none";
    alertShown = false;
  }, 400);
}


// ---------------- Severity ----------------
function updateSevBars(logs) {
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  logs.forEach(l => {
    if (counts[l.severity] !== undefined) {
      counts[l.severity]++;
    }
  });

  const total = logs.length || 1;

  document.getElementById("bCrit").style.width = (counts.CRITICAL / total * 100) + "%";
  document.getElementById("bHigh").style.width = (counts.HIGH / total * 100) + "%";
  document.getElementById("bMed").style.width  = (counts.MEDIUM / total * 100) + "%";
  document.getElementById("bLow").style.width  = (counts.LOW / total * 100) + "%";

  document.getElementById("nCrit").textContent = counts.CRITICAL;
  document.getElementById("nHigh").textContent = counts.HIGH;
  document.getElementById("nMed").textContent  = counts.MEDIUM;
  document.getElementById("nLow").textContent  = counts.LOW;
}


// ---------------- Threat Level ----------------
function updateThreatLevel(count) {
  const ts3 = document.getElementById("ts3");
  const ts4 = document.getElementById("ts4");
  const ts5 = document.getElementById("ts5");
  const txt = document.getElementById("tlText");

  if (count < 5) {
    ts3.classList.remove("on");
    ts4.classList.remove("on");
    ts5.classList.remove("on");
    txt.textContent = "LOW";
    txt.style.color = "#00ff9d";
  }
  else if (count < 20) {
    ts3.classList.add("on");
    ts4.classList.remove("on");
    ts5.classList.remove("on");
    txt.textContent = "MODERATE";
    txt.style.color = "#ff9f0a";
  }
  else if (count < 50) {
    ts3.classList.add("on");
    ts4.classList.add("on");
    ts5.classList.remove("on");
    txt.textContent = "HIGH";
    txt.style.color = "#ff9f0a";
  }
  else {
    ts3.classList.add("on");
    ts4.classList.add("on");
    ts5.classList.add("on");
    txt.textContent = "CRITICAL";
    txt.style.color = "#ff2d55";
  }
}


// ---------------- Incident Response ----------------
let selectedThreatId = null;

function incidentAction(action) {
  if (!selectedThreatId) {
    addTerminal("No incident selected", "warn");
    return;
  }

  const row = document.querySelector(`[data-id="${selectedThreatId}"]`);
  if (!row) return;

  const badge = row.querySelector(".status-badge");
  if (!badge) return;

  let status = "Detected";

  if (action === "investigate") status = "Investigating";
  if (action === "block") status = "Blocked";
  if (action === "quarantine") status = "Contained";
  if (action === "resolve") status = "Resolved";
  if (action === "ignore") status = "Ignored";

  badge.textContent = status;

  addTerminal(`Incident #${selectedThreatId} -> ${status}`, "ok");
}


// ---------------- Render Logs ----------------
function renderLogs(logs) {
  const tbody = document.getElementById("logBody");
  tbody.innerHTML = "";

  logs.forEach((l, i) => {
    const tr = document.createElement("tr");

    tr.className = `log-row sev-${l.severity.toLowerCase()}`;
    tr.setAttribute("data-id", l.id);

    const stClass = l.status.toLowerCase().replace(" ", "_");

    tr.innerHTML = `
      <td class="muted">#${l.id}</td>
      <td>${l.time}</td>
      <td class="attack-name">${l.attack}</td>
      <td class="ip-addr">${l.ip}</td>
      <td><span class="sev-badge sev-${l.severity.toLowerCase()}">${l.severity}</span></td>
      <td><span class="status-badge st-${stClass}">${l.status}</span></td>
    `;

    tr.onclick = () => {
      document.querySelectorAll("#logBody tr").forEach(x => x.style.outline = "none");

      tr.style.outline = "1px solid #00ff9d";
      selectedThreatId = l.id;

      addTerminal(`Incident selected #${l.id}`, "warn");
    };

    tbody.appendChild(tr);
  });

  document.getElementById("logCount").textContent = logs.length + " ENTRIES";
}


// ---------------- Refresh ----------------
async function refresh() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;

    const data = await res.json();

    document.getElementById("packetCount").textContent =
      data.packet_count.toLocaleString();

    document.getElementById("threatCount").textContent =
      data.threat_count;

    document.getElementById("lastScan").textContent =
      data.last_scan;

    renderLogs(data.logs);
    updateSevBars(data.logs);
    updateThreatLevel(data.threat_count);

    if (data.threat_count >= 10 && !alertShown) {
      alertShown = true;
      showAlert(
        `${data.threat_count} threats detected this session. Immediate review recommended.`
      );
    }

  } catch (e) {
    console.warn(e);
  }
}

setInterval(refresh, 6000);
refresh();


// ---------------- Add Threat ----------------
const MANUAL_ATTACKS = [
  "ARP Spoofing",
  "MITM Attack",
  "DDoS Flood",
  "Port Scan",
  "SQL Injection",
  "Brute Force"
];

const MANUAL_SEV = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL"
];

const MANUAL_STAT = [
  "Blocked",
  "Investigating",
  "Detected"
];

async function simulateThreat() {
  const body = {
    attack: MANUAL_ATTACKS[Math.floor(Math.random() * MANUAL_ATTACKS.length)],
    ip: `10.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`,
    severity: MANUAL_SEV[Math.floor(Math.random() * MANUAL_SEV.length)],
    status: MANUAL_STAT[Math.floor(Math.random() * MANUAL_STAT.length)]
  };

  await fetch("/add-threat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  addTerminal("Manual threat injected", "warn");
  refresh();
}

async function clearLogs() {
  if (!confirm("Clear all logs?")) return;

  await fetch("/clear-logs", {
    method: "POST"
  });

  addTerminal("Threat database cleared", "err");
  refresh();
}

function rand(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}