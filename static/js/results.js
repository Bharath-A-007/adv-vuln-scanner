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
        riskLevel =
