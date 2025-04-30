// Protocol Analysis JavaScript for Network Traffic Analysis Tool

// Global variables
let protocolChart = null;
let tcpFlagsChart = null;
let protocolTimeChart = null;
let refreshInterval = null;

// Initialize the protocol analysis page
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Load initial data
    loadProtocolDistribution();
    loadTcpFlagsAnalysis();
    loadProtocolOverTime();
    
    // Set up event listeners
    setupEventListeners();
});

// Set up event listeners
function setupEventListeners() {
    // Time range selector for protocol distribution
    const protocolTimeRange = document.getElementById('protocol-time-range');
    if (protocolTimeRange) {
        protocolTimeRange.addEventListener('change', function() {
            loadProtocolDistribution(this.value);
        });
    }
    
    // Time range selector for TCP flags analysis
    const tcpFlagsTimeRange = document.getElementById('tcp-flags-time-range');
    if (tcpFlagsTimeRange) {
        tcpFlagsTimeRange.addEventListener('change', function() {
            loadTcpFlagsAnalysis(this.value);
        });
    }
    
    // Time range and interval selectors for protocol over time
    const protocolOverTimeRange = document.getElementById('protocol-over-time-range');
    const protocolOverTimeInterval = document.getElementById('protocol-over-time-interval');
    
    if (protocolOverTimeRange) {
        protocolOverTimeRange.addEventListener('change', function() {
            const interval = protocolOverTimeInterval ? protocolOverTimeInterval.value : '5m';
            loadProtocolOverTime(this.value, interval);
        });
    }
    
    if (protocolOverTimeInterval) {
        protocolOverTimeInterval.addEventListener('change', function() {
            const timeRange = protocolOverTimeRange ? protocolOverTimeRange.value : '1h';
            loadProtocolOverTime(timeRange, this.value);
        });
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refresh-protocol-data');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            const protocolTimeRange = document.getElementById('protocol-time-range');
            const tcpFlagsTimeRange = document.getElementById('tcp-flags-time-range');
            const protocolOverTimeRange = document.getElementById('protocol-over-time-range');
            const protocolOverTimeInterval = document.getElementById('protocol-over-time-interval');
            
            const protocolRange = protocolTimeRange ? protocolTimeRange.value : '1h';
            const tcpFlagsRange = tcpFlagsTimeRange ? tcpFlagsTimeRange.value : '1h';
            const timeSeriesRange = protocolOverTimeRange ? protocolOverTimeRange.value : '1h';
            const timeSeriesInterval = protocolOverTimeInterval ? protocolOverTimeInterval.value : '5m';
            
            loadProtocolDistribution(protocolRange);
            loadTcpFlagsAnalysis(tcpFlagsRange);
            loadProtocolOverTime(timeSeriesRange, timeSeriesInterval);
        });
    }
    
    // Auto-refresh toggle
    const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', function() {
            if (this.checked) {
                // Start auto-refresh (every 30 seconds)
                startAutoRefresh(30);
            } else {
                // Stop auto-refresh
                stopAutoRefresh();
            }
        });
    }
}

// Initialize charts
function initCharts() {
    // Protocol distribution chart
    const protocolCtx = document.getElementById('protocol-distribution-chart');
    if (protocolCtx) {
        protocolChart = new Chart(protocolCtx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#0d6efd', // Bootstrap primary
                        '#20c997', // Bootstrap teal
                        '#0dcaf0', // Bootstrap info
                        '#ffc107', // Bootstrap warning
                        '#fd7e14', // Bootstrap orange
                        '#dc3545', // Bootstrap danger
                        '#6f42c1', // Bootstrap purple
                        '#6c757d', // Bootstrap secondary
                        '#198754', // Bootstrap success
                        '#343a40'  // Bootstrap dark
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const dataset = context.dataset;
                                const total = dataset.data.reduce((acc, data) => acc + data, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${percentage}% (${formatBytes(value)})`;
                            }
                        }
                    }
                }
            }
        });
    }
    
    // TCP flags chart
    const tcpFlagsCtx = document.getElementById('tcp-flags-chart');
    if (tcpFlagsCtx) {
        tcpFlagsChart = new Chart(tcpFlagsCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packet Count',
                    data: [],
                    backgroundColor: 'rgba(13, 110, 253, 0.7)',
                    borderColor: 'rgba(13, 110, 253, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false,
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
    
    // Protocol over time chart
    const protocolTimeCtx = document.getElementById('protocol-over-time-chart');
    if (protocolTimeCtx) {
        protocolTimeChart = new Chart(protocolTimeCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: []
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                stacked: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed.y !== null) {
                                    label += formatBytes(context.parsed.y);
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            maxTicksLimit: 8
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return formatBytes(value, 1);
                            }
                        }
                    }
                }
            }
        });
    }
}

// Load protocol distribution data
function loadProtocolDistribution(timeRange = '1h') {
    const distributionContainer = document.getElementById('protocol-distribution-container');
    const chartContainer = document.getElementById('protocol-distribution-chart-container');
    
    if (!distributionContainer || !chartContainer) return;
    
    // Show loading state
    chartContainer.innerHTML = '<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border" role="status"></div></div>';
    
    // Fetch protocol distribution from API
    fetch(`/api/protocol-analysis/distribution?time_range=${timeRange}`)
        .then(response => response.json())
        .then(data => {
            // Update chart
            updateProtocolDistributionChart(data.protocols);
            
            // Update table
            updateProtocolDistributionTable(data.protocols);
            
            // Show chart container
            chartContainer.innerHTML = '<canvas id="protocol-distribution-chart"></canvas>';
            initCharts(); // Re-initialize chart
            updateProtocolDistributionChart(data.protocols);
        })
        .catch(error => {
            console.error('Error loading protocol distribution:', error);
            chartContainer.innerHTML = `<div class="alert alert-danger">Error loading protocol distribution: ${error.message}</div>`;
        });
}

// Update protocol distribution chart
function updateProtocolDistributionChart(protocols) {
    if (!protocolChart || !protocols || protocols.length === 0) return;
    
    // Sort by percentage (descending)
    protocols.sort((a, b) => b.percentage - a.percentage);
    
    // Limit to top protocols (to avoid cluttering the chart)
    const maxProtocols = 8;
    let topProtocols = protocols.slice(0, maxProtocols);
    
    // If there are more protocols, aggregate the rest into "Other"
    if (protocols.length > maxProtocols) {
        const otherProtocols = protocols.slice(maxProtocols);
        const otherBytes = otherProtocols.reduce((sum, p) => sum + p.byte_count, 0);
        const otherPercentage = otherProtocols.reduce((sum, p) => sum + p.percentage, 0);
        
        topProtocols.push({
            protocol: 'Other',
            byte_count: otherBytes,
            packet_count: otherProtocols.reduce((sum, p) => sum + p.packet_count, 0),
            percentage: otherPercentage
        });
    }
    
    // Extract data for chart
    const labels = topProtocols.map(p => p.protocol);
    const values = topProtocols.map(p => p.byte_count);
    
    // Update chart data
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = values;
    
    // Redraw the chart
    protocolChart.update();
}

// Update protocol distribution table
function updateProtocolDistributionTable(protocols) {
    const tableBody = document.getElementById('protocol-distribution-table-body');
    if (!tableBody) return;
    
    // Clear existing rows
    tableBody.innerHTML = '';
    
    // Sort by percentage (descending)
    protocols.sort((a, b) => b.percentage - a.percentage);
    
    // Add rows for each protocol
    protocols.forEach(protocol => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${protocol.protocol}</td>
            <td>${formatBytes(protocol.byte_count)}</td>
            <td>${protocol.packet_count.toLocaleString()}</td>
            <td>
                <div class="progress" style="height: 10px;">
                    <div class="progress-bar" role="progressbar" style="width: ${protocol.percentage}%;" 
                         aria-valuenow="${protocol.percentage}" aria-valuemin="0" aria-valuemax="100"></div>
                </div>
                <small>${protocol.percentage.toFixed(1)}%</small>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
}

// Load TCP flags analysis data
function loadTcpFlagsAnalysis(timeRange = '1h') {
    const flagsContainer = document.getElementById('tcp-flags-container');
    const chartContainer = document.getElementById('tcp-flags-chart-container');
    
    if (!flagsContainer || !chartContainer) return;
    
    // Show loading state
    chartContainer.innerHTML = '<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border" role="status"></div></div>';
    
    // Fetch TCP flags data from API
    fetch(`/api/protocol-analysis/tcp-flags?time_range=${timeRange}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Update chart
            updateTcpFlagsChart(data.tcp_flags);
            
            // Update table
            updateTcpFlagsTable(data.tcp_flags);
            
            // Show chart container
            chartContainer.innerHTML = '<canvas id="tcp-flags-chart"></canvas>';
            initCharts(); // Re-initialize chart
            updateTcpFlagsChart(data.tcp_flags);
        })
        .catch(error => {
            console.error('Error loading TCP flags analysis:', error);
            chartContainer.innerHTML = `<div class="alert alert-danger">Error loading TCP flags analysis: ${error.toString()}</div>`;
        });
}

// Update TCP flags chart
function updateTcpFlagsChart(tcpFlags) {
    if (!tcpFlagsChart || !tcpFlags || tcpFlags.length === 0) return;
    
    // Sort by count (descending)
    tcpFlags.sort((a, b) => b.count - a.count);
    
    // Limit to top flag combinations (to avoid cluttering the chart)
    const maxFlags = 10;
    const topFlags = tcpFlags.slice(0, maxFlags);
    
    // Extract data for chart
    const labels = topFlags.map(f => f.flags);
    const values = topFlags.map(f => f.count);
    
    // Update chart data
    tcpFlagsChart.data.labels = labels;
    tcpFlagsChart.data.datasets[0].data = values;
    
    // Redraw the chart
    tcpFlagsChart.update();
}

// Update TCP flags table
function updateTcpFlagsTable(tcpFlags) {
    const tableBody = document.getElementById('tcp-flags-table-body');
    if (!tableBody) return;
    
    // Clear existing rows
    tableBody.innerHTML = '';
    
    // Sort by count (descending)
    tcpFlags.sort((a, b) => b.count - a.count);
    
    // Add rows for each flag combination
    tcpFlags.forEach(flag => {
        const row = document.createElement('tr');
        
        // Format flags with coloring
        let flagsHtml = '<span class="tcp-flags">';
        for (let i = 0; i < flag.flags.length; i++) {
            flagsHtml += `<span class="flag-${flag.flags[i]}">${flag.flags[i]}</span>`;
        }
        flagsHtml += '</span>';
        
        row.innerHTML = `
            <td>${flagsHtml}</td>
            <td>${flag.count.toLocaleString()}</td>
            <td>${flag.description}</td>
        `;
        
        tableBody.appendChild(row);
    });
}

// Load protocol over time data
function loadProtocolOverTime(timeRange = '1h', interval = '5m') {
    const chartContainer = document.getElementById('protocol-over-time-chart-container');
    
    if (!chartContainer) return;
    
    // Show loading state
    chartContainer.innerHTML = '<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border" role="status"></div></div>';
    
    // Fetch protocol over time data from API
    fetch(`/api/protocol-analysis/protocol-over-time?time_range=${timeRange}&interval=${interval}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Show chart container
            chartContainer.innerHTML = '<canvas id="protocol-over-time-chart"></canvas>';
            initCharts(); // Re-initialize chart
            
            // Update chart
            updateProtocolOverTimeChart(data.time_series);
        })
        .catch(error => {
            console.error('Error loading protocol over time data:', error);
            chartContainer.innerHTML = `<div class="alert alert-danger">Error loading protocol over time data: ${error.toString()}</div>`;
        });
}

// Update protocol over time chart
function updateProtocolOverTimeChart(timeSeriesData) {
    if (!protocolTimeChart || !timeSeriesData || timeSeriesData.length === 0) return;
    
    // Extract timestamps for labels
    const timestamps = timeSeriesData.map(entry => {
        const date = new Date(entry.timestamp);
        return date.toLocaleTimeString();
    });
    
    // Get all protocols present in the data
    const allProtocols = new Set();
    timeSeriesData.forEach(entry => {
        Object.keys(entry).forEach(key => {
            if (key !== 'timestamp') {
                allProtocols.add(key);
            }
        });
    });
    
    // Prepare datasets, one for each protocol
    const datasets = [];
    const colors = [
        '#0d6efd', // primary
        '#20c997', // teal
        '#0dcaf0', // info
        '#ffc107', // warning
        '#fd7e14', // orange
        '#dc3545', // danger
        '#6f42c1', // purple
        '#6c757d', // secondary
        '#198754', // success
        '#343a40'  // dark
    ];
    
    // Convert the set to an array and sort
    const protocols = Array.from(allProtocols).sort();
    
    protocols.forEach((protocol, index) => {
        const color = colors[index % colors.length];
        
        const dataPoints = timeSeriesData.map(entry => entry[protocol] || 0);
        
        datasets.push({
            label: protocol,
            data: dataPoints,
            borderColor: color,
            backgroundColor: `${color}33`, // Add alpha channel for transparency
            borderWidth: 2,
            fill: false,
            tension: 0.4
        });
    });
    
    // Update chart data
    protocolTimeChart.data.labels = timestamps;
    protocolTimeChart.data.datasets = datasets;
    
    // Redraw the chart
    protocolTimeChart.update();
}

// Start auto-refresh
function startAutoRefresh(seconds) {
    // Clear existing interval
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    // Set new interval
    refreshInterval = setInterval(() => {
        // Get current selections
        const protocolTimeRange = document.getElementById('protocol-time-range');
        const tcpFlagsTimeRange = document.getElementById('tcp-flags-time-range');
        const protocolOverTimeRange = document.getElementById('protocol-over-time-range');
        const protocolOverTimeInterval = document.getElementById('protocol-over-time-interval');
        
        const protocolRange = protocolTimeRange ? protocolTimeRange.value : '1h';
        const tcpFlagsRange = tcpFlagsTimeRange ? tcpFlagsTimeRange.value : '1h';
        const timeSeriesRange = protocolOverTimeRange ? protocolOverTimeRange.value : '1h';
        const timeSeriesInterval = protocolOverTimeInterval ? protocolOverTimeInterval.value : '5m';
        
        // Refresh all data
        loadProtocolDistribution(protocolRange);
        loadTcpFlagsAnalysis(tcpFlagsRange);
        loadProtocolOverTime(timeSeriesRange, timeSeriesInterval);
    }, seconds * 1000);
    
    console.log(`Auto-refresh started: every ${seconds} seconds`);
}

// Stop auto-refresh
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
        console.log('Auto-refresh stopped');
    }
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show alert-animated`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    }, 5000);
}
