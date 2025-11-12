// Main JavaScript functionality for Web Doc Scanner

// Global variables
let currentScanId = null;
let scanInProgress = false;

// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    // Check for existing scan results
    const savedResults = localStorage.getItem('webDocScanResults');
    if (savedResults) {
        try {
            const results = JSON.parse(savedResults);
            if (results.scan_date) {
                showRecentScanNotification(results);
            }
        } catch (e) {
            console.error('Error loading saved results:', e);
            localStorage.removeItem('webDocScanResults');
        }
    }
    
    // Initialize risk meter
    updateRiskMeter(0);
}

function setupEventListeners() {
    // URL input enter key support
    const urlInput = document.getElementById('target-url');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                startScan();
            }
        });
    }
    
    // Scan type change
    const scanTypeRadios = document.querySelectorAll('input[name="scan-type"]');
    scanTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            updateScanEstimate(this.value);
        });
    });
}

function startScan() {
    if (scanInProgress) {
        alert('A scan is already in progress. Please wait for it to complete.');
        return;
    }
    
    const urlInput = document.getElementById('target-url');
    const url = urlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a target URL', 'error');
        urlInput.focus();
        return;
    }
    
    // Validate URL format
    if (!isValidUrl(url)) {
        showNotification('Please enter a valid URL (e.g., https://example.com)', 'error');
        return;
    }
    
    const scanType = document.querySelector('input[name="scan-type"]:checked').value;
    
    // Show loading state
    showLoadingState(true);
    scanInProgress = true;
    
    // Start the scan
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url,
            scan_type: scanType
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Store results
        localStorage.setItem('webDocScanResults', JSON.stringify(data));
        currentScanId = data.scan_id;
        
        // Redirect to results page
        window.location.href = '/results';
    })
    .catch(error => {
        console.error('Scan failed:', error);
        showNotification(`Scan failed: ${error.message}`, 'error');
    })
    .finally(() => {
        showLoadingState(false);
        scanInProgress = false;
    });
}

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

function showLoadingState(show) {
    const loadingElement = document.getElementById('loading');
    const scanButton = document.querySelector('.scan-btn');
    
    if (show) {
        loadingElement.style.display = 'flex';
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        }
        
        // Simulate progress for better UX
        simulateProgress();
    } else {
        loadingElement.style.display = 'none';
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        }
    }
}

function simulateProgress() {
    const progressFill = document.getElementById('progress-fill');
    if (!progressFill) return;
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress >= 90) {
            progress = 90; // Cap at 90% until real completion
        }
        progressFill.style.width = progress + '%';
        
        if (!scanInProgress) {
            clearInterval(interval);
            progressFill.style.width = '100%';
        }
    }, 500);
}

function updateScanEstimate(scanType) {
    const estimateElement = document.getElementById('scan-estimate');
    if (!estimateElement) return;
    
    const estimates = {
        'quick': '1-2 minutes',
        'comprehensive': '5-10 minutes'
    };
    
    estimateElement.textContent = `Estimated time: ${estimates[scanType]}`;
}

function updateRiskMeter(score) {
    const fill = document.getElementById('risk-fill');
    const scoreDisplay = document.getElementById('risk-score');
    
    if (!fill || !scoreDisplay) return;
    
    fill.style.width = score + '%';
    scoreDisplay.textContent = score + '/100';
    
    // Update color based on risk
    if (score >= 70) {
        fill.style.background = '#e74c3c'; // Red
    } else if (score >= 40) {
        fill.style.background = '#f39c12'; // Orange
    } else {
        fill.style.background = '#2ecc71'; // Green
    }
}

function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => notification.remove());
    
    // Create new notification
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        background: ${getNotificationColor(type)};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        max-width: 400px;
        animation: slideInRight 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'info': 'info-circle',
        'success': 'check-circle',
        'warning': 'exclamation-triangle',
        'error': 'exclamation-circle'
    };
    return icons[type] || 'info-circle';
}

function getNotificationColor(type) {
    const colors = {
        'info': '#3b82f6',
        'success': '#10b981',
        'warning': '#f59e0b',
        'error': '#ef4444'
    };
    return colors[type] || '#3b82f6';
}

function showRecentScanNotification(results) {
    const timeDiff = Date.now() - new Date(results.scan_date).getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    
    if (hoursDiff < 24) { // Show only if scan was in last 24 hours
        showNotification(
            `Recent scan results available for ${results.target_url}`, 
            'info'
        );
    }
}

// Utility function to format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Export functions for global access
window.startScan = startScan;
window.showNotification = showNotification;
