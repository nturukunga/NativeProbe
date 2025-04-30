// Dashboard JavaScript for Network Traffic Analysis Tool

// Global variables for charts
let bandwidthChart = null;
let protocolChart = null;
let trafficChart = null;
let refreshInterval = null;

// Initialize the dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Load initial data
    loadDashboardData();
    
    // Set up automatic refresh
    const refreshRate = document.getElementById('refresh-rate');
    if (refreshRate) {
        refreshRate.addEventListener('change', function() {
            updateRefreshInterval(parseInt(this.value));
        });
        
        // Initial setup with default refresh rate
        updateRefreshInterval(parseInt(refreshRate.value));
    }
    
    // Handle manual refresh
    const refreshButton = document.getElementById('refresh-dashboard');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            loadDashboardData();
        });
    }
});

// Initialize dashboard charts
function initCharts() {
    // Bandwidth usage chart
    const bandwidthCtx = document.getElementById('bandwidth-chart');
    if (bandwidthCtx) {
        charts.bandwidth = new Chart(bandwidthCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Inbound',
                        data: [],
                        borderColor: '#0dcaf0', // Bootstrap info color
                        backgroundColor: 'rgba(13, 202, 240, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Outbound',
                        data: [],
                        borderColor: '#6c757d', // Bootstrap secondary color
                        backgroundColor: 'rgba(108, 117, 125, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
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
    
    // Protocol distribution chart
    const protocolCtx = document.getElementById('protocol-chart');
    if (protocolCtx) {
        protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#0dcaf0', // Bootstrap info
                        '#20c997', // Bootstrap teal
                        '#0d6efd', // Bootstrap primary
                        '#ffc107', // Bootstrap warning
                        '#6f42c1', // Bootstrap purple
                        '#fd7e14', // Bootstrap orange
                        '#dc3545', // Bootstrap danger
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
                                return `${label}: ${percentage}%`;
                            }
                        }
                    }
                }
            }
        });
    }
    
    // Traffic over time chart
    const trafficCtx = document.getElementById('traffic-chart');
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    backgroundColor: 'rgba(13, 202, 240, 0.5)',
                    borderColor: 'rgba(13, 202, 240, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false,
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            maxTicksLimit: 6
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
}

// Load dashboard data from API
// Global chart objects
let charts = {
    bandwidth: null,
    protocol: null,
    traffic: null
};

function loadDashboardData() {
    if (!charts.bandwidth) {
        initCharts();
    }
    // Update UI to show loading state
    document.querySelectorAll('.chart-loading').forEach(el => {
        el.style.display = 'flex';
    });
    
    // Fetch dashboard summary data
    fetch('/api/dashboard/summary')
        .then(response => response.json())
        .then(data => {
            updateBandwidthChart(data.bandwidth);
            updateProtocolChart(data.protocols);
            updateAnomalyList(data.anomalies);
            updateActiveCaptures(data.active_captures);
            
            // Hide loading indicators
            document.querySelectorAll('.chart-loading').forEach(el => {
                el.style.display = 'none';
            });
        })
        .catch(error => {
            console.error('Error loading dashboard data:', error);
            // Show error message to user
            const alertContainer = document.getElementById('alert-container');
            if (alertContainer) {
                alertContainer.innerHTML = `
                    <div class="alert alert-danger alert-animated alert-dismissible fade show" role="alert">
                        Failed to load dashboard data: ${error.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
            }
            
            // Hide loading indicators
            document.querySelectorAll('.chart-loading').forEach(el => {
                el.style.display = 'none';
            });
        });
    
    // Update live statistics
    updateLiveStats();
}

// Update bandwidth chart with new data
function updateBandwidthChart(bandwidthData) {
    if (!bandwidthChart || !bandwidthData || bandwidthData.length === 0) return;
    
    // Process and sort data chronologically
    bandwidthData.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
    // Limit data points to prevent chart from becoming too crowded
    const maxDataPoints = 20;
    if (bandwidthData.length > maxDataPoints) {
        bandwidthData = bandwidthData.slice(bandwidthData.length - maxDataPoints);
    }
    
    // Extract data for chart
    const labels = bandwidthData.map(d => {
        const date = new Date(d.timestamp);
        return date.toLocaleTimeString();
    });
    
    const bytesIn = bandwidthData.map(d => d.bytes_in);
    const bytesOut = bandwidthData.map(d => d.bytes_out);
    
    // Update chart data
    bandwidthChart.data.labels = labels;
    bandwidthChart.data.datasets[0].data = bytesIn;
    bandwidthChart.data.datasets[1].data = bytesOut;
    
    // Redraw the chart
    bandwidthChart.update();
}

// Update protocol distribution chart
function updateProtocolChart(protocolData) {
    if (!protocolChart || !protocolData || protocolData.length === 0) return;
    
    // Sort by percentage (descending)
    protocolData.sort((a, b) => b.percentage - a.percentage);
    
    // Limit to top protocols (to avoid cluttering the chart)
    const maxProtocols = 6;
    let topProtocols = protocolData.slice(0, maxProtocols);
    
    // If there are more protocols, aggregate the rest into "Other"
    if (protocolData.length > maxProtocols) {
        const otherProtocols = protocolData.slice(maxProtocols);
        const otherBytes = otherProtocols.reduce((sum, p) => sum + p.byte_count, 0);
        const otherPercentage = otherProtocols.reduce((sum, p) => sum + p.percentage, 0);
        
        topProtocols.push({
            protocol: 'Other',
            byte_count: otherBytes,
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
    
    // Update protocol table
    updateProtocolTable(protocolData);
}

// Update protocol table
function updateProtocolTable(protocolData) {
    const protocolTable = document.getElementById('protocol-table-body');
    if (!protocolTable) return;
    
    // Clear existing rows
    protocolTable.innerHTML = '';
    
    // Add rows for each protocol
    protocolData.forEach(protocol => {
        const row = document.createElement('tr');
        
        // Apply protocol-specific styling
        row.classList.add(`protocol-${protocol.protocol.toLowerCase()}`);
        
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
        
        protocolTable.appendChild(row);
    });
}

// Update anomaly list
function updateAnomalyList(anomalies) {
    const anomalyList = document.getElementById('anomaly-list');
    if (!anomalyList) return;
    
    // Clear existing items
    anomalyList.innerHTML = '';
    
    // Add list items for each anomaly
    if (anomalies && anomalies.length > 0) {
        anomalies.forEach(anomaly => {
            const li = document.createElement('li');
            li.className = `list-group-item severity-${anomaly.severity} d-flex justify-content-between align-items-center`;
            
            // Format timestamp
            const anomalyTime = new Date(anomaly.timestamp);
            const timeString = anomalyTime.toLocaleTimeString();
            
            // Icon based on severity
            let icon = 'info-circle';
            if (anomaly.severity >= 4) {
                icon = 'exclamation-circle';
            } else if (anomaly.severity >= 3) {
                icon = 'exclamation-triangle';
            } else if (anomaly.severity >= 2) {
                icon = 'question-circle';
            }
            
            li.innerHTML = `
                <div>
                    <div class="fw-bold">
                        <i class="fas fa-${icon} me-2 anomaly-icon"></i>
                        ${anomaly.event_type}
                    </div>
                    <small>${anomaly.description}</small>
                </div>
                <span class="badge bg-secondary rounded-pill">${timeString}</span>
            `;
            
            anomalyList.appendChild(li);
        });
    } else {
        // No anomalies
        const li = document.createElement('li');
        li.className = 'list-group-item text-center';
        li.innerHTML = '<em>No anomalies detected</em>';
        anomalyList.appendChild(li);
    }
    
    // Update anomaly count badge
    const anomalyCount = document.getElementById('anomaly-count');
    if (anomalyCount) {
        const count = anomalies ? anomalies.length : 0;
        anomalyCount.textContent = count;
        
        if (count > 0) {
            anomalyCount.classList.remove('bg-secondary');
            anomalyCount.classList.add('bg-danger');
        } else {
            anomalyCount.classList.remove('bg-danger');
            anomalyCount.classList.add('bg-secondary');
        }
    }
}

// Update active captures table
function updateActiveCaptures(captures) {
    const capturesTable = document.getElementById('active-captures-body');
    if (!capturesTable) return;
    
    // Clear existing rows
    capturesTable.innerHTML = '';
    
    // Add rows for each active capture
    if (captures && captures.length > 0) {
        captures.forEach(capture => {
            const row = document.createElement('tr');
            
            // Format start time
            const startTime = new Date(capture.start_time);
            const timeString = startTime.toLocaleString();
            
            row.innerHTML = `
                <td>${capture.name}</td>
                <td>${capture.interface}</td>
                <td>${timeString}</td>
                <td>${capture.packet_count.toLocaleString()}</td>
                <td>${capture.filter_expression || '<em>None</em>'}</td>
                <td>
                    <button class="btn btn-sm btn-danger stop-capture" data-capture-id="${capture.id}">
                        <i class="fas fa-stop me-1"></i> Stop
                    </button>
                </td>
            `;
            
            capturesTable.appendChild(row);
        });
        
        // Add event listeners to stop buttons
        document.querySelectorAll('.stop-capture').forEach(button => {
            button.addEventListener('click', function() {
                const captureId = this.getAttribute('data-capture-id');
                stopCapture(captureId);
            });
        });
    } else {
        // No active captures
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="6" class="text-center"><em>No active captures</em></td>';
        capturesTable.appendChild(row);
    }
    
    // Update capture count badge
    const captureCount = document.getElementById('capture-count');
    if (captureCount) {
        const count = captures ? captures.length : 0;
        captureCount.textContent = count;
        
        if (count > 0) {
            captureCount.classList.remove('bg-secondary');
            captureCount.classList.add('bg-primary');
        } else {
            captureCount.classList.remove('bg-primary');
            captureCount.classList.add('bg-secondary');
        }
    }
}

// Stop a packet capture
function stopCapture(captureId) {
    fetch(`/api/packet-analysis/stop-capture/${captureId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show success message
            const alertContainer = document.getElementById('alert-container');
            if (alertContainer) {
                alertContainer.innerHTML = `
                    <div class="alert alert-success alert-animated alert-dismissible fade show" role="alert">
                        Capture stopped successfully
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
            }
            
            // Refresh dashboard data
            loadDashboardData();
        } else {
            throw new Error(data.error || 'Failed to stop capture');
        }
    })
    .catch(error => {
        console.error('Error stopping capture:', error);
        // Show error message
        const alertContainer = document.getElementById('alert-container');
        if (alertContainer) {
            alertContainer.innerHTML = `
                <div class="alert alert-danger alert-animated alert-dismissible fade show" role="alert">
                    Failed to stop capture: ${error.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
        }
    });
}

// Update live stats from API
function updateLiveStats() {
    fetch('/api/dashboard/live-stats')
        .then(response => response.json())
        .then(data => {
            updateBandwidthStats(data.bandwidth);
            updateProtocolStats(data.protocols);
        })
        .catch(error => {
            console.error('Error updating live stats:', error);
        });
}

// Update bandwidth statistics
function updateBandwidthStats(data) {
    if (!data) return;
    
    // Update bandwidth stats
    const inRateEl = document.getElementById('in-rate');
    const outRateEl = document.getElementById('out-rate');
    const totalBandwidthEl = document.getElementById('total-bandwidth');
    
    if (inRateEl && data.bytes_in !== undefined) {
        inRateEl.textContent = formatBytes(data.bytes_in);
    }
    
    if (outRateEl && data.bytes_out !== undefined) {
        outRateEl.textContent = formatBytes(data.bytes_out);
    }
    
    if (totalBandwidthEl && data.bytes_in !== undefined && data.bytes_out !== undefined) {
        const total = data.bytes_in + data.bytes_out;
        totalBandwidthEl.textContent = formatBytes(total);
    }
}

// Update protocol statistics
function updateProtocolStats(protocols) {
    if (!protocols || protocols.length === 0) return;
    
    // Update top protocol display
    const topProtocolEl = document.getElementById('top-protocol');
    if (topProtocolEl) {
        // Find protocol with highest percentage
        const topProtocol = protocols.reduce((prev, current) => 
            (prev.percentage > current.percentage) ? prev : current
        );
        
        topProtocolEl.textContent = `${topProtocol.protocol} (${topProtocol.percentage.toFixed(1)}%)`;
    }
}

// Set up or update the refresh interval
function updateRefreshInterval(seconds) {
    // Clear existing interval
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    // Use a faster refresh rate for real-time updates
    const refreshRate = Math.max(1, Math.min(seconds, 5)); // 1-5 second refresh
    
    // Set up new interval if seconds > 0
    if (seconds > 0) {
        refreshInterval = setInterval(loadDashboardData, seconds * 1000);
        console.log(`Auto-refresh set to ${seconds} seconds`);
    } else {
        console.log('Auto-refresh disabled');
    }
}
