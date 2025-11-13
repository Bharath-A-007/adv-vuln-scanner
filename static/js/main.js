[file name]: static/js/main.js
[file content begin]
// Vulnerability data
const vulnerabilityData = {
    owasp2021: [
        { name: 'A01: Broken Access Control', severity: 'high' },
        { name: 'A02: Cryptographic Failures', severity: 'high' },
        { name: 'A03: Injection', severity: 'critical' },
        { name: 'A04: Insecure Design', severity: 'medium' },
        { name: 'A05: Security Misconfiguration', severity: 'medium' },
        { name: 'A06: Vulnerable Components', severity: 'high' },
        { name: 'A07: Identification Failures', severity: 'high' },
        { name: 'A08: Software/Data Integrity', severity: 'medium' },
        { name: 'A09: Security Logging Failures', severity: 'low' },
        { name: 'A10: Server-Side Request Forgery', severity: 'high' }
    ],
    owasp2025: [
        { name: 'A01: Broken Access Control', severity: 'high' },
        { name: 'A02: Cryptographic Failures', severity: 'high' },
        { name: 'A03: Injection', severity: 'critical' },
        { name: 'A04: Insecure Design', severity: 'medium' },
        { name: 'A05: Security Misconfiguration', severity: 'medium' },
        { name: 'A06: Vulnerable Components', severity: 'high' },
        { name: 'A07: Identification Failures', severity: 'high' },
        { name: 'A08: Software/Data Integrity', severity: 'medium' },
        { name: 'A09: Security Logging Failures', severity: 'low' },
        { name: 'A10: Server-Side Request Forgery', severity: 'high' }
    ],
    riskAnalysis: [
        { name: 'SSL/TLS Configuration Check', severity: 'high' },
        { name: 'Security Headers Analysis', severity: 'medium' },
        { name: 'Cookie Security Assessment', severity: 'medium' },
        { name: 'HTTP Method Analysis', severity: 'low' },
        { name: 'Information Disclosure Check', severity: 'medium' },
        { name: 'Cross-Origin Resource Sharing', severity: 'medium' },
        { name: 'Content Security Policy', severity: 'high' },
        { name: 'XSS Protection Headers', severity: 'high' },
        { name: 'Frame Options Check', severity: 'medium' },
        { name: 'MIME Type Security', severity: 'low' }
    ]
};

// Initialize vulnerability lists
document.addEventListener('DOMContentLoaded', function() {
    initializeVulnerabilityLists();
    setupHoverEvents();
});

function initializeVulnerabilityLists() {
    // Initialize all lists with top 5 items
    Object.keys(vulnerabilityData).forEach(category => {
        const listElement = document.getElementById(`${category}-list`);
        const items = vulnerabilityData[category];
        
        // Show only top 5 initially
        const visibleItems = items.slice(0, 5);
        
        visibleItems.forEach(item => {
            const itemElement = createVulnerabilityItem(item);
            listElement.appendChild(itemElement);
        });
    });
}

function createVulnerabilityItem(item) {
    const div = document.createElement('div');
    div.className = `vulnerability-item ${item.severity}`;
    div.textContent = item.name;
    return div;
}

function toggleCategory(categoryId) {
    const category = document.getElementById(categoryId);
    const list = document.getElementById(`${categoryId}-list`);
    const button = category.querySelector('.expand-btn');
    const buttonText = button.querySelector('span');
    const buttonIcon = button.querySelector('svg');
    
    if (category.classList.contains('collapsed')) {
        // Expand to show all items
        list.innerHTML = '';
        vulnerabilityData[categoryId].forEach(item => {
            const itemElement = createVulnerabilityItem(item);
            list.appendChild(itemElement);
        });
        category.classList.remove('collapsed');
        buttonText.textContent = 'Show Less';
        buttonIcon.style.transform = 'rotate(180deg)';
    } else {
        // Collapse to show only top 5
        list.innerHTML = '';
        const visibleItems = vulnerabilityData[categoryId].slice(0, 5);
        visibleItems.forEach(item => {
            const itemElement = createVulnerabilityItem(item);
            list.appendChild(itemElement);
        });
        category.classList.add('collapsed');
        buttonText.textContent = 'Show All';
        buttonIcon.style.transform = 'rotate(0deg)';
    }
}

function setupHoverEvents() {
    const categories = ['owasp2021', 'owasp2025', 'riskAnalysis'];
    
    categories.forEach(categoryId => {
        const category = document.getElementById(categoryId);
        
        category.addEventListener('mouseenter', function() {
            if (this.classList.contains('collapsed')) {
                toggleCategory(categoryId);
            }
        });
        
        category.addEventListener('mouseleave', function() {
            if (!this.classList.contains('collapsed')) {
                toggleCategory(categoryId);
            }
        });
    });
}

// Scan form handling
document.getElementById('scanForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const url = document.getElementById('targetUrl').value;
    const scanType = document.querySelector('input[name="scanType"]:checked').value;
    const scanButton = document.getElementById('scanButton');
    
    if (!url) {
        alert('Please enter a valid URL');
        return;
    }
    
    // Update button text
    scanButton.textContent = 'Scanning...';
    scanButton.disabled = true;
    
    // Perform scan
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
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Scan failed: ' + data.error);
        } else {
            // Redirect to results page with scan ID
            window.location.href = `/results?scan_id=${data.scan_id}`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Scan failed. Please try again.');
    })
    .finally(() => {
        // Reset button
        scanButton.textContent = 'Start Security Scan';
        scanButton.disabled = false;
    });
});
[file content end]
