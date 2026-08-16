// PhishGuard Security Suite — Frontend Logic

// ==================== TAB SWITCHING ====================
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

    document.getElementById('tab-' + tab).classList.add('active');
    document.getElementById(tab + '-panel').classList.add('active');
}

// ==================== PHISHING DETECTION ====================
async function scanUrl() {
    const input = document.getElementById('urlInput');
    const url = input.value.trim();
    const btn = document.getElementById('scanBtn');

    if (!url) { showError('Please enter a URL to scan'); return; }

    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.remove('hidden');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';

    try {
        const response = await fetch('/api/detect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        if (data.error) { showError(data.error); return; }
        displayPhishingResults(data);
    } catch (err) {
        showError('Failed to connect to server. Make sure Flask is running on port 5000.');
    } finally {
        document.getElementById('loading').classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'SCAN';
    }
}

function displayPhishingResults(data) {
    const results = document.getElementById('results');
    results.classList.remove('hidden');

    const gauge = document.getElementById('gaugeCircle');
    gauge.style.borderColor = data.risk_color;
    document.getElementById('riskScore').textContent = data.risk_score;

    const riskLevel = document.getElementById('riskLevel');
    riskLevel.textContent = data.risk_level + ' RISK';
    riskLevel.style.color = data.risk_color;

    document.getElementById('scannedUrl').textContent = data.url;
    document.getElementById('legitBar').style.width = data.legitimate_probability + '%';
    document.getElementById('legitPct').textContent = data.legitimate_probability + '%';
    document.getElementById('phishBar').style.width = data.phishing_probability + '%';
    document.getElementById('phishPct').textContent = data.phishing_probability + '%';

    document.getElementById('suspiciousCount').textContent = data.suspicious_features;
    document.getElementById('totalFeatures').textContent = data.total_features;
    const verdict = document.getElementById('verdict');
    verdict.textContent = data.is_phishing ? 'PHISHING' : 'SAFE';
    verdict.style.color = data.is_phishing ? 'var(--red)' : 'var(--green)';

    const featureList = document.getElementById('featureList');
    featureList.innerHTML = '';
    data.features.forEach(f => {
        const item = document.createElement('div');
        item.className = 'feature-item' + (f.suspicious ? ' suspicious' : '');
        let displayVal = f.value;
        if (typeof f.value === 'number' && f.value % 1 !== 0) displayVal = f.value.toFixed(3);
        item.innerHTML = `
            <span class="feature-icon">${f.suspicious ? '⚠️' : '✓'}</span>
            <span class="feature-name">${f.name}</span>
            <span class="feature-value">${displayVal}</span>
            ${f.note ? `<span class="feature-note">${f.note}</span>` : ''}
        `;
        featureList.appendChild(item);
    });
    results.scrollIntoView({ behavior: 'smooth' });
}

// ==================== NETWORK SCANNER ====================
async function scanNetwork() {
    const input = document.getElementById('targetInput');
    const target = input.value.trim();
    const btn = document.getElementById('scanNetBtn');

    if (!target) { showNetError('Please enter a target to scan'); return; }

    document.getElementById('netResults').classList.add('hidden');
    document.getElementById('netError').classList.add('hidden');
    document.getElementById('netLoading').classList.remove('hidden');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        const data = await response.json();
        if (data.error) { showNetError(data.error); return; }
        displayScanResults(data);
    } catch (err) {
        showNetError('Failed to connect to server. Make sure Flask is running on port 5000.');
    } finally {
        document.getElementById('netLoading').classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'SCAN';
    }
}

function displayScanResults(data) {
    const results = document.getElementById('netResults');
    results.classList.remove('hidden');

    // Risk gauge
    let riskColor;
    if (data.risk_score >= 75) riskColor = '#FF3D00';
    else if (data.risk_score >= 50) riskColor = '#FF3D00';
    else if (data.risk_score >= 25) riskColor = '#FFD600';
    else riskColor = '#00C853';

    const gauge = document.getElementById('netGaugeCircle');
    gauge.style.borderColor = riskColor;
    document.getElementById('netRiskScore').textContent = data.risk_score;

    const riskLevel = document.getElementById('netRiskLevel');
    riskLevel.textContent = data.risk_level;
    riskLevel.style.color = riskColor;

    document.getElementById('scannedTarget').textContent = data.target;
    document.getElementById('portsScanned').textContent = data.ports_scanned;
    document.getElementById('portsOpen').textContent = data.ports_open;
    document.getElementById('resolvedIp').textContent = data.resolved_ip;

    // Count risk levels
    const highCount = data.open_ports.filter(p => p.risk_level === 'HIGH').length;
    const medCount = data.open_ports.filter(p => p.risk_level === 'MEDIUM').length;
    const lowCount = data.open_ports.filter(p => p.risk_level === 'LOW').length;

    document.getElementById('highRiskPorts').textContent = highCount;
    document.getElementById('mediumRiskPorts').textContent = medCount;
    document.getElementById('lowRiskPorts').textContent = lowCount;

    const verdict = document.getElementById('netVerdict');
    if (data.risk_score >= 75) { verdict.textContent = 'CRITICAL'; verdict.style.color = 'var(--red)'; }
    else if (data.risk_score >= 50) { verdict.textContent = 'AT RISK'; verdict.style.color = 'var(--red)'; }
    else if (data.risk_score >= 25) { verdict.textContent = 'CAUTION'; verdict.style.color = 'var(--yellow)'; }
    else { verdict.textContent = 'SECURE'; verdict.style.color = 'var(--green)'; }

    // Summary
    document.getElementById('scanSummary').textContent = data.summary;

    // Port list
    const portList = document.getElementById('portList');
    portList.innerHTML = '';

    if (data.open_ports.length === 0) {
        portList.innerHTML = '<div class="feature-item low-risk"><span class="feature-icon">✓</span><span class="feature-name">No open ports detected — minimal attack surface</span></div>';
    } else {
        data.open_ports.forEach(p => {
            const riskClass = p.risk_level.toLowerCase();
            const item = document.createElement('div');
            item.className = `port-item ${riskClass}`;
            item.innerHTML = `
                <span class="port-num">:${p.port}</span>
                <span class="port-service">${p.service}</span>
                <span class="port-risk ${riskClass}">${p.risk_level}</span>
                <span></span>
            `;

            if (p.banner || p.vulnerability) {
                const detail = document.createElement('div');
                detail.className = 'port-detail';
                detail.style.display = 'block';
                let html = '';
                if (p.banner) html += `<div class="port-banner">Banner: ${p.banner}</div>`;
                if (p.vulnerability) html += `<div class="port-vuln">⚠️ ${p.vulnerability}</div>`;
                detail.innerHTML = html;

                const wrapper = document.createElement('div');
                wrapper.appendChild(item);
                wrapper.appendChild(detail);
                portList.appendChild(wrapper);
            } else {
                portList.appendChild(item);
            }
        });
    }

    results.scrollIntoView({ behavior: 'smooth' });
}

// ==================== HELPERS ====================
function testUrl(url) {
    document.getElementById('urlInput').value = url;
    scanUrl();
}

function testTarget(target) {
    document.getElementById('targetInput').value = target;
    scanNetwork();
}

function showError(msg) {
    document.getElementById('error').textContent = msg;
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
}

function showNetError(msg) {
    document.getElementById('netError').textContent = msg;
    document.getElementById('netError').classList.remove('hidden');
    document.getElementById('netLoading').classList.add('hidden');
    document.getElementById('netResults').classList.add('hidden');
}

// Enter key support
document.getElementById('urlInput').addEventListener('keypress', e => {
    if (e.key === 'Enter') scanUrl();
});
document.getElementById('targetInput').addEventListener('keypress', e => {
    if (e.key === 'Enter') scanNetwork();
});
