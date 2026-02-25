// ===== ANALYSIS =====
async function submitAnalysis(e) {
    e.preventDefault();

    var threatType = document.getElementById('threatType').value;
    var description = document.getElementById('description').value.trim();

    if (!description) {
        var ta = document.getElementById('description');
        ta.style.animation = 'shake 0.4s';
        ta.focus();
        setTimeout(function() { ta.style.animation = ''; }, 400);
        return;
    }

    // Show loading
    document.getElementById('stateEmpty').style.display = 'none';
    document.getElementById('stateResult').style.display = 'none';
    document.getElementById('stateLoading').style.display = 'flex';

    // Disable button
    var btn = document.getElementById('submitBtn');
    btn.disabled = true;
    btn.textContent = 'Analyzing...';

    // Animate loading steps
    var steps = document.querySelectorAll('#loaderSteps .loader-step');
    var bar = document.getElementById('loaderBarFill');
    steps.forEach(function(s) { s.classList.remove('active', 'done'); });
    bar.style.width = '0%';

    for (var i = 0; i < steps.length; i++) {
        await sleep(700);
        if (i > 0) { steps[i - 1].classList.remove('active'); steps[i - 1].classList.add('done'); }
        steps[i].classList.add('active');
        bar.style.width = ((i + 1) / steps.length * 100) + '%';
    }

    try {
        var res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: 'demo-user-' + Math.random().toString(36).substring(2, 8),
                threat_type: threatType,
                description: description,
            }),
        });
        var data = await res.json();

        // Finish loading
        steps[steps.length - 1].classList.remove('active');
        steps[steps.length - 1].classList.add('done');
        bar.style.width = '100%';
        await sleep(400);

        displayResult(data);
    } catch (err) {
        console.error('Analysis error:', err);
        document.getElementById('stateLoading').style.display = 'none';
        document.getElementById('stateEmpty').style.display = 'flex';
    }

    btn.disabled = false;
    btn.textContent = 'Broadcast to Subnet Miners';
}

function displayResult(data) {
    document.getElementById('stateLoading').style.display = 'none';
    document.getElementById('stateResult').style.display = 'block';

    // Top bar
    var badge = document.getElementById('resultBadge');
    badge.textContent = data.risk_level.toUpperCase();
    badge.className = 'result-badge badge-' + data.risk_level;

    document.getElementById('resultThreatName').textContent = data.threat_name;
    document.getElementById('resultTime').textContent = data.analysis_time_seconds + 's';
    document.getElementById('resultMiners').textContent = data.miner_nodes_consulted + ' miners';
    document.getElementById('resultConfidence').textContent = data.confidence_score + '%';

    // Risk gauge
    var score = data.risk_score;
    var arc = document.getElementById('riskArc');
    var dashOffset = 314 - (314 * score / 100);
    var riskColor = getRiskColor(data.risk_level);

    arc.style.stroke = riskColor;
    arc.style.strokeDashoffset = '314';
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            arc.style.strokeDashoffset = dashOffset;
        });
    });

    var scoreEl = document.getElementById('riskScore');
    scoreEl.textContent = score;
    scoreEl.style.color = riskColor;

    // Risk details
    document.getElementById('resultCategory').textContent = data.category;
    var riskLevelEl = document.getElementById('resultRiskLevel');
    riskLevelEl.textContent = data.risk_level;
    riskLevelEl.className = 'risk-detail-value risk-' + data.risk_level;
    document.getElementById('resultSubnet').textContent = 'v' + data.subnet_version;

    // ===== MINER RESPONSES =====
    document.getElementById('minerCount').textContent = data.miner_responses.length + ' miners responded';
    document.getElementById('minerList').innerHTML = data.miner_responses.map(function(m) {
        var scoreClass = m.score >= 0.90 ? 'score-high' : (m.score >= 0.75 ? 'score-mid' : 'score-low');
        var topClass = m.rank === 1 ? ' top-miner' : '';
        var specialtyHtml = m.specialty ? '<span class="miner-specialty">' + escapeHtml(m.specialty) + '</span>' : '';
        return '<div class="miner-card' + topClass + '">' +
            '<div class="miner-top-row">' +
                '<div class="miner-identity">' +
                    '<span class="miner-rank">#' + m.rank + '</span>' +
                    '<div>' +
                        '<div class="miner-name">' + escapeHtml(m.name) + specialtyHtml + '</div>' +
                        '<div class="miner-hotkey">' + escapeHtml(m.hotkey) + ' · UID ' + m.uid + '</div>' +
                    '</div>' +
                '</div>' +
                '<span class="miner-score-badge ' + scoreClass + '">' + m.score.toFixed(4) + '</span>' +
            '</div>' +
            '<div class="miner-analysis">' + escapeHtml(m.analysis) + '</div>' +
            '<div class="miner-meta">' +
                '<span class="miner-meta-item">⏱ ' + m.response_time_s + 's</span>' +
                '<span class="miner-meta-item">Risk: ' + escapeHtml(m.risk_assessed) + '</span>' +
            '</div>' +
        '</div>';
    }).join('');

    // ===== VALIDATOR RESULTS =====
    document.getElementById('validatorCount').textContent = data.validator_results.length + ' validators verified';
    document.getElementById('validatorList').innerHTML = data.validator_results.map(function(v) {
        var checksHtml = '';
        if (v.check_details) {
            var keys = Object.keys(v.check_details);
            checksHtml = keys.map(function(label) {
                var passed = v.check_details[label];
                var icon = passed ? '✓' : '✗';
                var cls = passed ? 'check-pass' : 'check-fail';
                return '<span class="check-item ' + cls + '">' + icon + ' ' + escapeHtml(label) + '</span>';
            }).join('');
        }
        var specialtyHtml = v.specialty ? '<span class="validator-specialty">' + escapeHtml(v.specialty) + '</span>' : '';
        return '<div class="validator-card">' +
            '<div class="validator-top-row">' +
                '<div class="validator-identity">' +
                    '<span class="validator-icon">' +
                        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a3e635" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
                    '</span>' +
                    '<div>' +
                        '<div class="validator-name">' + escapeHtml(v.name) + specialtyHtml + '</div>' +
                        '<div class="validator-hotkey">' + escapeHtml(v.hotkey) + ' · UID ' + v.uid + '</div>' +
                    '</div>' +
                '</div>' +
                '<span class="validator-consensus consensus-' + v.consensus + '">' + v.consensus + '</span>' +
            '</div>' +
            '<div class="validator-checks">' + checksHtml + '</div>' +
            '<div class="validator-meta">' +
                '<span class="validator-meta-item">Stake: ' + v.stake_tao.toFixed(2) + ' τ</span>' +
                '<span class="validator-meta-item">VTrust: ' + v.vtrust.toFixed(4) + '</span>' +
                '<span class="validator-meta-item">Checks: ' + v.checks_passed + '/' + v.checks_total + '</span>' +
            '</div>' +
        '</div>';
    }).join('');

    // ===== CONSENSUS =====
    document.getElementById('consensusStatus').textContent = data.consensus_reached ? 'Reached ✓' : 'Pending...';
    document.getElementById('consensusStatus').className = 'consensus-value ' + (data.consensus_reached ? 'consensus-approved' : '');
    document.getElementById('blockNumber').textContent = '#' + data.block_number.toLocaleString();
    document.getElementById('taoReward').textContent = data.tao_reward_pool.toFixed(4) + ' τ';

    // Indicators of Compromise
    document.getElementById('iocTags').innerHTML = data.indicators
        .map(function(i) { return '<span class="tag tag-red">' + escapeHtml(i) + '</span>'; })
        .join('');

    // Mitigation
    document.getElementById('mitigationText').textContent = data.mitigation;

    // Recommendation
    document.getElementById('recommendationText').textContent = data.recommendation;

    // Affected Systems
    document.getElementById('systemTags').innerHTML = data.affected_systems
        .map(function(s) { return '<span class="tag tag-amber">' + escapeHtml(s) + '</span>'; })
        .join('');

    // CVE References
    if (data.cve_references && data.cve_references.length > 0 && data.cve_references[0] !== '') {
        document.getElementById('cveSection').style.display = 'block';
        document.getElementById('cveTags').innerHTML = data.cve_references
            .map(function(c) { return '<span class="tag tag-purple">' + escapeHtml(c) + '</span>'; })
            .join('');
    } else {
        document.getElementById('cveSection').style.display = 'none';
    }

    // Timestamp
    var ts = new Date(data.timestamp);
    document.getElementById('resultTimestamp').textContent =
        ts.toLocaleDateString() + ' ' + ts.toLocaleTimeString() + ' UTC';
}

function resetAnalysis() {
    document.getElementById('stateResult').style.display = 'none';
    document.getElementById('stateEmpty').style.display = 'flex';
    document.getElementById('description').value = '';
    document.getElementById('riskArc').style.strokeDashoffset = '314';
}

// ===== HELPERS =====
function getRiskColor(level) {
    var colors = {
        Critical: '#f87171',
        High: '#fbbf24',
        Medium: '#22d3ee',
        Low: '#a3e635'
    };
    return colors[level] || '#22d3ee';
}

function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
}
