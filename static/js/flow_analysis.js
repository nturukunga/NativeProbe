// Flow Analysis JavaScript for Network Traffic Analysis Tool

// Global variables
let flowsTable = null;
let currentPage = 1;
let totalPages = 1;
let collectorActive = false;
let flowChartsInitialized = false;
let topSourcesChart = null;
let topDestinationsChart = null;
let protocolDistributionChart = null;

// Initialize the flow analysis page
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listeners
    setupEventListeners();
    
    // Load initial data
    checkCollectorStatus();
    loadFlowData();
    loadTopTalkers();
});

// Set up event listeners
function setupEventListeners() {
    // Start collector form
    const startCollectorForm = document.getElementById('start-collector-form');
    if (startCollectorForm) {
        startCollectorForm.addEventListener('submit', function(event) {
            event.preventDefault();
            startFlowCollector();
        });
    }
    
    // Stop collector button
    const stopCollectorBtn = document.getElementById('stop-collector');
    if (stopCollectorBtn) {
        stopCollectorBtn.addEventListener('click', stopFlowCollector);
    }
    
    // Pagination controls
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', function() {
            if (currentPage > 1) {
                currentPage--;
                loadFlowData(currentPage);
            }
        });
    }
    
    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', function() {
            if (currentPage < totalPages) {
                currentPage++;
                loadFlowData(currentPage);
            }
        });
    }
    
    // Flow filter form
    const flowFilterForm = document.getElementById('flow-filter-form');
    if (flowFilterForm) {
        flowFilterForm.addEventListener('submit', function(event) {
            event.preventDefault();
            currentPage = 1; // Reset to first page
            loadFlowData(1);
        });
    }
    
    // Time range selector for top talkers
    const topTalkersTimeRange = document.getElementById('top-talkers-time-range');
    if (topTalkersTimeRange) {
        topTalkersTimeRange.addEventListener('change', function() {
            loadTopTalkers(this.value);
        });
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refresh-flows');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadFlowData(currentPage);
            loadTopTalkers();
        });
    }
}

// Check if flow collector is running
function checkCollectorStatus() {
    // This is a simplified implementation since we don't have a direct endpoint to check status
    // In a real application, you would have an API endpoint to get collector status
    
    // For now, we'll just update the UI based on our local state
    updateCollectorStatus(collectorActive);
}

// Update collector status in UI
function updateCollectorStatus(isActive) {
    collectorActive = isActive;
    
    const statusBadge = document.getElementById('collector-status');
    const startCollectorBtn = document.querySelector('#start-collector-form button[type="submit"]');
    const stopCollectorBtn = document.getElementById('stop-collector');
    
    if (statusBadge) {
        if (isActive) {
            statusBadge.className = 'badge bg-success';
            statusBadge.textContent = 'Active';
        } else {
            statusBadge.className = 'badge bg-secondary';
            statusBadge.textContent = 'Inactive';
        }
    }
    
    if (startCollectorBtn) {
        startCollectorBtn.disabled = isActive;
    }
    
    if (stopCollectorBtn) {
        stopCollectorBtn.disabled = !isActive;
    }
}

// Start flow collector
function startFlowCollector() {
    const flowTypeEl = document.getElementById('flow-type');
    const portEl = document.getElementById('collector-port');
    
    const flowType = flowTypeEl ? flowTypeEl.value : 'netflow';
    const port = portEl ? parseInt(portEl.value) : 9995;
    
    // Validate input
    if (isNaN(port) || port < 1 || port > 65535) {
        showAlert('Please enter a valid port number (1-65535)', 'danger');
        return;
    }
    
    // Show loading state
    const startButton = document.querySelector('#start-collector-form button[type="submit"]');
    const originalButtonText = startButton.innerHTML;
    startButton.disabled = true;
    startButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Send request to start collector
    fetch('/api/flow-analysis/start-collector', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            flow_type: flowType,
            port: port
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert(`Flow collector (${flowType}) started successfully on port ${port}`, 'success');
            
            // Update collector status
            updateCollectorStatus(true);
            
            // Close modal if it exists
            const modal = bootstrap.Modal.getInstance(document.getElementById('start-collector-modal'));
            if (modal) {
                modal.hide();
            }
        } else {
            throw new Error(result.error || 'Failed to start flow collector');
        }
    })
    .catch(error => {
        console.error('Error starting flow collector:', error);
        showAlert(`Error starting flow collector: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        startButton.disabled = false;
        startButton.innerHTML = originalButtonText;
    });
}

// Stop flow collector
function stopFlowCollector() {
    // Confirm before stopping
    if (!confirm('Are you sure you want to stop the flow collector?')) {
        return;
    }
    
    // Show loading state
    const stopButton = document.getElementById('stop-collector');
    const originalButtonText = stopButton.innerHTML;
    stopButton.disabled = true;
    stopButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Stopping...';
    
    // Send request to stop collector
    fetch('/api/flow-analysis/stop-collector', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert('Flow collector stopped successfully', 'success');
            
            // Update collector status
            updateCollectorStatus(false);
        } else {
            throw new Error(result.error || 'Failed to stop flow collector');
        }
    })
    .catch(error => {
        console.error('Error stopping flow collector:', error);
        showAlert(`Error stopping flow collector: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        stopButton.disabled = false;
        stopButton.innerHTML = originalButtonText;
    });
}

// Load flow data
function loadFlowData(page = 1) {
    const flowsTableBody = document.getElementById('flows-table-body');
    const paginationInfo = document.getElementById('pagination-info');
    
    if (!flowsTableBody) return;
    
    // Show loading state
    flowsTableBody.innerHTML = '<tr><td colspan="8" class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Loading flow data...</td></tr>';
    
    // Build query parameters from filter form
    const params = new URLSearchParams();
    params.append('page', page);
    params.append('per_page', 50);
    
    // Add filter parameters
    const flowType = document.getElementById('filter-flow-type');
    const sourceIp = document.getElementById('filter-source-ip');
    const destIp = document.getElementById('filter-dest-ip');
    const startTime = document.getElementById('filter-start-time');
    const endTime = document.getElementById('filter-end-time');
    
    if (flowType && flowType.value) {
        params.append('flow_type', flowType.value);
    }
    
    if (sourceIp && sourceIp.value) {
        params.append('source_ip', sourceIp.value);
    }
    
    if (destIp && destIp.value) {
        params.append('destination_ip', destIp.value);
    }
    
    if (startTime && startTime.value) {
        params.append('start_time', new Date(startTime.value).toISOString());
    }
    
    if (endTime && endTime.value) {
        params.append('end_time', new Date(endTime.value).toISOString());
    }
    
    // Fetch flows from API
    fetch(`/api/flow-analysis/flows?${params.toString()}`)
        .then(response => response.json())
        .then(data => {
            // Update pagination info
            currentPage = data.current_page;
            totalPages = data.pages;
            
            if (paginationInfo) {
                paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${data.total} flows)`;
            }
            
            // Update pagination buttons
            const prevPageBtn = document.getElementById('prev-page');
            const nextPageBtn = document.getElementById('next-page');
            
            if (prevPageBtn) {
                prevPageBtn.disabled = currentPage === 1;
            }
            
            if (nextPageBtn) {
                nextPageBtn.disabled = currentPage === totalPages;
            }
            
            // Clear existing rows
            flowsTableBody.innerHTML = '';
            
            // Add flow rows
            if (data.flows && data.flows.length > 0) {
                data.flows.forEach((flow, index) => {
                    const row = document.createElement('tr');
                    
                    // Format timestamp
                    const timestamp = new Date(flow.timestamp);
                    const timeStr = timestamp.toLocaleString();
                    
                    // Determine protocol name
                    let protocolName = flow.protocol;
                    if (flow.protocol === 6) protocolName = 'TCP';
                    else if (flow.protocol === 17) protocolName = 'UDP';
                    else if (flow.protocol === 1) protocolName = 'ICMP';
                    
                    row.innerHTML = `
                        <td>${index + 1 + (currentPage - 1) * 50}</td>
                        <td>${timeStr}</td>
                        <td>${flow.flow_type}</td>
                        <td>${flow.source_ip}${flow.source_port ? ':' + flow.source_port : ''}</td>
                        <td>${flow.destination_ip}${flow.destination_port ? ':' + flow.destination_port : ''}</td>
                        <td>${protocolName}</td>
                        <td>${formatBytes(flow.bytes)}</td>
                        <td>${flow.packets.toLocaleString()}</td>
                    `;
                    
                    flowsTableBody.appendChild(row);
                });
            } else {
                // No flows found
                flowsTableBody.innerHTML = '<tr><td colspan="8" class="text-center">No flow records found</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error loading flows:', error);
            flowsTableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Error loading flows: ${error.message}</td></tr>`;
        });
}

// Load top talkers data
function loadTopTalkers(timeRange = '1h') {
    const topTalkersContainer = document.getElementById('top-talkers-container');
    
    if (!topTalkersContainer) return;
    
    // Show loading state
    topTalkersContainer.innerHTML = '<div class="text-center p-3"><div class="spinner-border" role="status"></div><p>Loading top talkers data...</p></div>';
    
    // Fetch top talkers from API
    fetch(`/api/flow-analysis/top-talkers?time_range=${timeRange}`)
        .then(response => response.json())
        .then(data => {
            // Create visualization
            let html = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Top Source IPs</h5>
                            </div>
                            <div class="card-body">
                                <div class="chart-container">
                                    <canvas id="top-sources-chart"></canvas>
                                </div>
                                <div class="table-responsive mt-3">
                                    <table class="table table-sm table-hover">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>Bytes</th>
                                                <th>Packets</th>
                                                <th>Flows</th>
                                            </tr>
                                        </thead>
                                        <tbody>
            `;
            
            // Add source IPs
            if (data.top_sources && data.top_sources.length > 0) {
                data.top_sources.forEach(source => {
                    html += `
                        <tr>
                            <td>${source.ip_address}</td>
                            <td>${formatBytes(source.bytes)}</td>
                            <td>${source.packets.toLocaleString()}</td>
                            <td>${source.flow_count.toLocaleString()}</td>
                        </tr>
                    `;
                });
            } else {
                html += '<tr><td colspan="4" class="text-center">No data available</td></tr>';
            }
            
            html += `
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Top Destination IPs</h5>
                            </div>
                            <div class="card-body">
                                <div class="chart-container">
                                    <canvas id="top-destinations-chart"></canvas>
                                </div>
                                <div class="table-responsive mt-3">
                                    <table class="table table-sm table-hover">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>Bytes</th>
                                                <th>Packets</th>
                                                <th>Flows</th>
                                            </tr>
                                        </thead>
                                        <tbody>
            `;
            
            // Add destination IPs
            if (data.top_destinations && data.top_destinations.length > 0) {
                data.top_destinations.forEach(dest => {
                    html += `
                        <tr>
                            <td>${dest.ip_address}</td>
                            <td>${formatBytes(dest.bytes)}</td>
                            <td>${dest.packets.toLocaleString()}</td>
                            <td>${dest.flow_count.toLocaleString()}</td>
                        </tr>
                    `;
                });
            } else {
                html += '<tr><td colspan="4" class="text-center">No data available</td></tr>';
            }
            
            html += `
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            topTalkersContainer.innerHTML = html;
            
            // Initialize charts
            initTopTalkersCharts(data);
        })
        .catch(error => {
            console.error('Error loading top talkers:', error);
            topTalkersContainer.innerHTML = `<div class="alert alert-danger">Error loading top talkers: ${error.message}</div>`;
        });
}

// Initialize charts for top talkers
function initTopTalkersCharts(data) {
    // Prepare data for source chart
    const sourceLabels = data.top_sources ? data.top_sources.map(s => s.ip_address) : [];
    const sourceData = data.top_sources ? data.top_sources.map(s => s.bytes) : [];
    
    // Prepare data for destination chart
    const destLabels = data.top_destinations ? data.top_destinations.map(d => d.ip_address) : [];
    const destData = data.top_destinations ? data.top_destinations.map(d => d.bytes) : [];
    
    // Get chart contexts
    const sourceCtx = document.getElementById('top-sources-chart');
    const destCtx = document.getElementById('top-destinations-chart');
    
    // Create charts
    if (sourceCtx && sourceLabels.length > 0) {
        // Destroy previous chart if it exists
        if (topSourcesChart) {
            topSourcesChart.destroy();
        }
        
        topSourcesChart = new Chart(sourceCtx, {
            type: 'bar',
            data: {
                labels: sourceLabels,
                datasets: [{
                    label: 'Traffic (bytes)',
                    data: sourceData,
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
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed.x !== null) {
                                    label += formatBytes(context.parsed.x);
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            callback: function(value) {
                                return formatBytes(value, 0);
                            }
                        }
                    }
                }
            }
        });
    }
    
    if (destCtx && destLabels.length > 0) {
        // Destroy previous chart if it exists
        if (topDestinationsChart) {
            topDestinationsChart.destroy();
        }
        
        topDestinationsChart = new Chart(destCtx, {
            type: 'bar',
            data: {
                labels: destLabels,
                datasets: [{
                    label: 'Traffic (bytes)',
                    data: destData,
                    backgroundColor: 'rgba(32, 201, 151, 0.7)',
                    borderColor: 'rgba(32, 201, 151, 1)',
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
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed.x !== null) {
                                    label += formatBytes(context.parsed.x);
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            callback: function(value) {
                                return formatBytes(value, 0);
                            }
                        }
                    }
                }
            }
        });
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
