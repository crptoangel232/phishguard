// PhishGuard — Frontend Logic

async function scanUrl() {
    const input = document.getElementById('urlInput');
    const url = input.value.trim();
    const btn = document.getElementById('scanBtn');

    if (!url) {
        showError('Please enter a URL to scan');
        return;
    }

    // Show loading
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('infoSection').classList.add('hidden');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';

    try {
        const response = await fetch('/api/detect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        displayResults(data);
    } catch (err) {
        showError('Failed to connect to the server. Make sure the Flask server is running on port 5000.');
    } finally {
        document.getElementById('loading').classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'SCAN';
    }
}

function displayResults(data) {
    const results = document.getElementById('results');
    results.classList.remove('hidden');

    // Risk gauge
    const gauge = document.getElementById('gaugeCircle');
    gauge.style.borderColor = data.risk_color;
    document.getElementById('riskScore').textContent = data.risk_score;

    // Risk level
    const riskLevel = document.getElementById('riskLevel');
    riskLevel.textContent = data.risk_level + ' RISK';
    riskLevel.style.color = data.risk_color;

    // URL
    document.getElementById('scannedUrl').textContent = data.url;

    // Probabilities
    document.getElementById('legitBar').style.width = data.legitimate_probability + '%';
    document.getElementById('legitPct').textContent = data.legitimate_probability + '%';
    document.getElementById('phishBar').style.width = data.phishing_probability + '%';
    document.getElementById('phishPct').textContent = data.phishing_probability + '%';

    // Summary
    document.getElementById('suspiciousCount').textContent = data.suspicious_features;
    document.getElementById('totalFeatures').textContent = data.total_features;
    const verdict = document.getElementById('verdict');
    verdict.textContent = data.is_phishing ? 'PHISHING' : 'SAFE';
    verdict.style.color = data.is_phishing ? 'var(--red)' : 'var(--green)';

    // Feature breakdown
    const featureList = document.getElementById('featureList');
    featureList.innerHTML = '';

    data.features.forEach(f => {
        const item = document.createElement('div');
        item.className = 'feature-item' + (f.suspicious ? ' suspicious' : '');

        let displayValue = f.value;
        if (typeof f.value === 'number' && f.value % 1 !== 0) {
            displayValue = f.value.toFixed(3);
        }

        item.innerHTML = `
            <span class="feature-icon">${f.suspicious ? '⚠️' : '✓'}</span>
            <span class="feature-name">${f.name}</span>
            <span class="feature-value">${displayValue}</span>
            ${f.note ? `<span class="feature-note">${f.note}</span>` : ''}
        `;
        featureList.appendChild(item);
    });

    // Scroll to results
    results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function testUrl(url) {
    document.getElementById('urlInput').value = url;
    scanUrl();
}

function showError(msg) {
    const error = document.getElementById('error');
    error.textContent = msg;
    error.classList.remove('hidden');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('infoSection').classList.remove('hidden');
}

// Enter key support
document.getElementById('urlInput').addEventListener('keypress', e => {
    if (e.key === 'Enter') scanUrl();
});
