class SecurityCharts {
    constructor() {
        this.charts = {};
    }

    createRiskMeter(containerId, riskScore) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const meterHTML = `
            <div class="risk-meter-chart">
                <div class="meter-background">
                    <div class="meter-fill" style="width: ${riskScore}%"></div>
                </div>
                <div class="risk-labels">
                    <span>Low</span>
                    <span>Medium</span>
                    <span>High</span>
                    <span>Critical</span>
                </div>
                <div class="risk-score">${riskScore}/100</div>
            </div>
        `;

        container.innerHTML = meterHTML;
        this.updateMeterColor(container, riskScore);
    }

    updateMeterColor(container, score) {
        const fill = container.querySelector('.meter-fill');
        if (!fill) return;

        if (score >= 70) {
            fill.style.background = '#dc2626';
        } else if (score >= 50) {
            fill.style.background = '#ea580c';
        } else if (score >= 30) {
            fill.style.background = '#d97706';
        } else {
            fill.style.background = '#059669';
        }
    }

    createSeverityChart(containerId, severityData) {
        const ctx = document.getElementById(containerId);
        if (!ctx) return;

        // Simple SVG-based chart (no external dependencies)
        const total = severityData.critical + severityData.high + severityData.medium + severityData.low;
        
        const chartHTML = `
            <div class="severity-chart">
                <div class="chart-bars">
                    <div class="bar critical" style="height: ${(severityData.critical/total)*100}%">
                        <span class="bar-label">${severityData.critical}</span>
                    </div>
                    <div class="bar high" style="height: ${(severityData.high/total)*100}%">
                        <span class="bar-label">${severityData.high}</span>
                    </div>
                    <div class="bar medium" style="height: ${(severityData.medium/total)*100}%">
                        <span class="bar-label">${severityData.medium}</span>
                    </div>
                    <div class="bar low" style="height: ${(severityData.low/total)*100}%">
                        <span class="bar-label">${severityData.low}</span>
                    </div>
                </div>
                <div class="chart-labels">
                    <span>Critical</span>
                    <span>High</span>
                    <span>Medium</span>
                    <span>Low</span>
                </div>
            </div>
        `;

        ctx.innerHTML = chartHTML;
    }

    createOWASPDistribution(containerId, owaspData) {
        const container = document.getElementById(containerId);
        if (!container) return;

        let chartHTML = '<div class="owasp-distribution">';
        
        owaspData.forEach(category => {
            const percentage = (category.count / category.total) * 100;
            chartHTML += `
                <div class="owasp-category">
                    <div class="category-header">
                        <span class="category-name">${category.name}</span>
                        <span class="category-count">${category.count}</span>
                    </div>
                    <div class="category-bar">
                        <div class="category-fill" style="width: ${percentage}%"></div>
                    </div>
                </div>
            `;
        });

        chartHTML += '</div>';
        container.innerHTML = chartHTML;
    }

    createTimelineChart(containerId, timelineData) {
        // Implementation for timeline chart
        console.log('Creating timeline chart:', timelineData);
    }
}

// CSS for charts
const chartStyles = `
<style>
.risk-meter-chart {
    text-align: center;
    padding: 20px;
}

.meter-background {
    width: 100%;
    height: 30px;
    background: #f1f5f9;
    border-radius: 15px;
    overflow: hidden;
    margin-bottom: 10px;
    position: relative;
}

.meter-fill {
    height: 100%;
    border-radius: 15px;
    transition: all 0.5s ease;
}

.risk-labels {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
    margin-bottom: 10px;
}

.risk-score {
    font-size: 24px;
    font-weight: 700;
    color: #1e293b;
}

.severity-chart {
    display: flex;
    align-items: end;
    height: 200px;
    gap: 10px;
    padding: 20px;
}

.chart-bars {
    display: flex;
    align-items: end;
    gap: 15px;
    flex: 1;
    height: 100%;
}

.bar {
    flex: 1;
    border-radius: 4px 4px 0 0;
    position: relative;
    transition: height 0.5s ease;
    min-height: 20px;
}

.bar.critical { background: #dc2626; }
.bar.high { background: #ea580c; }
.bar.medium { background: #d97706; }
.bar.low { background: #059669; }

.bar-label {
    position: absolute;
    top: -25px;
    left: 50%;
    transform: translateX(-50%);
    font-weight: 600;
    color: #374151;
}

.chart-labels {
    display: flex;
    flex-direction: column;
    gap: 10px;
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
}

.owasp-distribution {
    padding: 20px;
}

.owasp-category {
    margin-bottom: 15px;
}

.category-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
    font-size: 14px;
}

.category-name {
    font-weight: 500;
    color: #374151;
}

.category-count {
    font-weight: 600;
    color: #1e293b;
}

.category-bar {
    height: 8px;
    background: #f1f5f9;
    border-radius: 4px;
    overflow: hidden;
}

.category-fill {
    height: 100%;
    background: #3b82f6;
    border-radius: 4px;
    transition: width 0.5s ease;
}
</style>
`;

// Inject styles
document.head.insertAdjacentHTML('beforeend', chartStyles);

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityCharts;
}
