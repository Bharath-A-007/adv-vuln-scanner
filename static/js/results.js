// Results page JavaScript functionality

let currentResults = null;

document.addEventListener('DOMContentLoaded', function() {
    loadResults();
    setupResultsPage();
});

function loadResults() {
    // Try to get results from localStorage first
    const savedResults = localStorage.getItem('webDocScanResults');
    
    if (savedResults) {
        try {
            currentResults = JSON.parse(savedResults);
            displayResults(currentResults);
            return;
        } catch (e) {
            console.error('Error parsing saved results:', e);
        }
    }
    
    // If no saved results, check URL parameters or show error
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    if (scanId) {
        fetchResults(scanId);
    } else {
        showError('No scan results found. Please perform a scan first.');
    }
}

function fetchResults(scanId) {
    fetch(`/api/results/${scanId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Results not found');
            }
            return response.json();
        })
        .then(results => {
            currentResults = results;
            displayResults(results);
            // Save to localStorage for persistence
            localStorage.setItem('webDocScanResults', JSON.stringify(results));
        })
        .catch(error => {
            console.error('Error fetching results:', error);
            showError('Could not load scan results: ' + error.message);
        });
}

function displayResults(results) {
    updateOverview(results);
    updateRiskMeter(results.risk_score);
    updateSummaryCards(results.findings);
    displayFindings(results.findings);
    
    // Store scan ID for PDF download
    window.currentScanId = results.scan_id;
}

function updateOverview(results) {
    document.getElementById('target-url').textContent = results.target_url;
    document.getElementById('scan-date').textContent = formatDate(results.scan_date);
    document.getElementById('total-findings').textContent = results.findings.length;
    document.getElementById('risk-level').textContent = results.risk_level;
    document.getElementById('risk-level').className = results.risk_level.toLowerCase();
}

function updateRiskMeter(score) {
    const fill = document.getElementById('risk-meter-fill');
    const scoreDisplay = document.getElementById('risk-score-large');
    const riskBadge = document.getElementById('risk-level');
    
    if (!fill) return;
    
    fill.style.width = score + '%';
    scoreDisplay.textContent = score + '/100';
    
    let riskLevel = 'Low';
    let riskClass = 'low';
    
    if (score >= 70) {
        riskLevel = 'Critical';
        riskClass = 'critical';
        fill.style.background = '#dc2626';
    } else if (score >= 50) {
        riskLevel = 'High';
        riskClass = 'high';
        fill.style.background = '#ea580c';
    } else if (score >= 30) {
        riskLevel = 'Medium';
        riskClass = 'medium';
        fill.style.background = '#d97706';
    } else {
        riskLevel = 'Low';
        riskClass = 'low';
        fill.style.background = '#059669';
    }
    
    if (riskBadge) {
        riskBadge.textContent = riskLevel;
        riskBadge.className = riskClass;
    }
}

function updateSummaryCards(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    
    findings.forEach(finding => {
        counts[finding.severity] += 1;
    });
    
    document.getElementById('critical-count').textContent = counts.CRITICAL;
    document.getElementById('high-count').textContent = counts.HIGH;
    document.getElementById('medium-count').textContent = counts.MEDIUM;
    document.getElementById('low-count').textContent = counts.LOW;
}

function displayFindings(findings) {
    const container = document.getElementById('findings-container');
    if (!container) return;
    
    container.innerHTML = '';
    
    // Group by severity
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    findings.forEach(finding => {
        bySeverity[finding.severity].push(finding);
    });
    
    // Display by severity order
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(severity => {
        if (bySeverity[severity].length > 0) {
            const severitySection = createSeveritySection(severity, bySeverity[severity]);
            container.appendChild(severitySection);
        }
    });
}

function createSeveritySection(severity, findings) {
    const section = document.createElement('div');
    section.className = `severity-section ${severity.toLowerCase()}`;
    
    const header = document.createElement('div');
    header.className = 'severity-header';
    header.innerHTML = `
        <h3>
            <i class="fas fa-${getSeverityIcon(severity)}"></i>
            ${severity} SEVERITY (${findings.length})
        </h3>
    `;
    
    const findingsList = document.createElement('div');
    findingsList.className = 'findings-list';
    
    findings.forEach((finding, index) => {
        const findingCard = document.createElement('div');
        findingCard.className = 'finding-card';
        findingCard.innerHTML = `
            <div class="finding-header">
                <span class="finding-title">${index + 1}. ${escapeHtml(finding.title)}</span>
                <span class="owasp-ref">${finding.owasp_ref}</span>
            </div>
            <div class="finding-description">
                <p>${escapeHtml(finding.description)}</p>
            </div>
            <div class="finding-actions">
                <button class="btn-sm btn-outline" onclick="showRemediation('${escapeHtml(finding.title)}', '${escapeHtml(finding.description)}', '${finding.owasp_ref}')">
                    <i class="fas fa-lightbulb"></i> Remediation
                </button>
            </div>
        `;
        findingsList.appendChild(findingCard);
    });
    
    section.appendChild(header);
    section.appendChild(findingsList);
    return section;
}

function getSeverityIcon(severity) {
    const icons = {
        'CRITICAL': 'exclamation-triangle',
        'HIGH': 'exclamation-circle',
        'MEDIUM': 'info-circle',
        'LOW': 'check-circle'
    };
    return icons[severity] || 'info-circle';
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showRemediation(title, description, owaspRef) {
    const remediation = getRemediationAdvice(owaspRef);
    
    // Create modal or show in notification
    showNotification(
        `<strong>Remediation for ${title}</strong><br>${remediation}`,
        'info'
    );
}

function getRemediationAdvice(owaspRef) {
    const advice = {
        'A01:2021': 'Implement proper access control checks. Use role-based access control (RBAC) and validate permissions on every request.',
        'A02:2021': 'Use HTTPS everywhere. Encrypt sensitive data and avoid weak cryptographic algorithms.',
        'A03:2021': 'Use parameterized queries and input validation. Escape all user inputs.',
        'A05:2021': 'Remove default credentials, disable unnecessary features, and secure configuration files.',
        'A07:2021': 'Implement strong authentication, use multi-factor authentication, and secure session management.'
    };
    
    return advice[owaspRef] || 'Review OWASP guidelines for this vulnerability category and implement recommended security controls.';
}

function downloadPDF() {
    if (window.currentScanId) {
        window.open(`/download-report?scan_id=${window.currentScanId}`, '_blank');
    } else {
        showNotification('No scan results available for download', 'error');
    }
}

function setupResultsPage() {
    // Add event listener for PDF download button
    const downloadBtn = document.querySelector('.download-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadPDF);
    }
    
    // Add keyboard shortcut for PDF download (Ctrl+D)
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
            e.preventDefault();
            downloadPDF();
        }
    });
}

function showError(message) {
    const container = document.getElementById('findings-container');
    if (container) {
        container.innerHTML = `
            <div class="error-state">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>No Results Available</h3>
                <p>${message}</p>
                <button class="btn btn-primary" onclick="window.location.href='/'">
                    <i class="fas fa-arrow-left"></i> Back to Scanner
                </button>
            </div>
        `;
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' at ' + date.toLocaleTimeString();
}

// Make functions globally available
window.downloadPDF = downloadPDF;
window.showRemediation = showRemediation;
