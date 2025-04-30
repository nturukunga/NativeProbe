// Anomaly Detection JavaScript for Network Traffic Analysis Tool

// Global variables
let anomaliesTable = null;
let currentPage = 1;
let totalPages = 1;
let severityChart = null;
let eventTypeChart = null;
let resolutionChart = null;
let detectionActive = false;

// Initialize the anomaly detection page
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Load initial data
    checkDetectionStatus();
    loadAnomalies();
    loadAnomalyStatistics();
    
    // Set up event listeners
    setupEventListeners();
});

// Set up event listeners
function setupEventListeners() {
    // Start detection form
    const startDetectionForm = document.getElementById('start-detection-form');
    if (startDetectionForm) {
        startDetectionForm.addEventListener('submit', function(event) {
            event.preventDefault();
            startAnomalyDetection();
        });
    }
    
    // Stop detection button
    const stopDetectionBtn = document.getElementById('stop-detection');
    if (stopDetectionBtn) {
        stopDetectionBtn.addEventListener('click', stopAnomalyDetection);
    }
    
    // Pagination controls
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', function() {
            if (currentPage > 1) {
                currentPage--;
                loadAnomalies(currentPage);
            }
        });
    }
    
    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', function() {
            if (currentPage < totalPages) {
                currentPage++;
                loadAnomalies(currentPage);
            }
        });
    }
    
    // Anomaly filter form
    const anomalyFilterForm = document.getElementById('anomaly-filter-form');
    if (anomalyFilterForm) {
        anomalyFilterForm.addEventListener('submit', function(event) {
            event.preventDefault();
            currentPage = 1; // Reset to first page
            loadAnomalies(1);
        });
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refresh-anomalies');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadAnomalies(currentPage);
            loadAnomalyStatistics();
        });
    }
}

// Check if anomaly detection is running
function checkDetectionStatus() {
    // This is a simplified implementation since we don't have a direct endpoint to check status
    // In a real application, you would have an API endpoint to get detection status
    
    // For now, we'll just update the UI based on our local state
    updateDetectionStatus(detectionActive);
}

// Update detection status in UI
function updateDetectionStatus(isActive) {
    detectionActive = isActive;
    
    const statusBadge = document.getElementById('detection-status');
    const startDetectionBtn = document.querySelector('#start-detection-form button[type="submit"]');
    const stopDetectionBtn = document.getElementById('stop-detection');
    
    if (statusBadge) {
        if (isActive) {
            statusBadge.className = 'badge bg-success';
            statusBadge.textContent = 'Active';
        } else {
            statusBadge.className = 'badge bg-secondary';
            statusBadge.textContent = 'Inactive';
        }
    }
    
    if (startDetectionBtn) {
        startDetectionBtn.disabled = isActive;
    }
    
    if (stopDetectionBtn) {
        stopDetectionBtn.disabled = !isActive;
    }
}

// Initialize charts
function initCharts() {
    // Severity distribution chart
    const severityCtx = document.getElementById('severity-chart');
    if (severityCtx) {
        severityChart = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['Info (1)', 'Low (2)', 'Medium (3)', 'High (4)', 'Critical (5)'],
                datasets: [{
                    label: 'Anomalies by Severity',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(13, 202, 240, 0.7)', // info
                        'rgba(25, 135, 84, 0.7)',  // success
                        'rgba(255, 193, 7, 0.7)',  // warning
                        'rgba(253, 126, 20, 0.7)', // orange
                        'rgba(220, 53, 69, 0.7)'   // danger
                    ],
                    borderColor: [
                        'rgba(13, 202, 240, 1)',
                        'rgba(25, 135, 84, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(253, 126, 20, 1)',
                        'rgba(220, 53, 69, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
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
    
    // Event type distribution chart
    const eventTypeCtx = document.getElementById('event-type-chart');
    if (eventTypeCtx) {
        eventTypeChart = new Chart(eventTypeCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        'rgba(13, 110, 253, 0.7)',  // primary
                        'rgba(32, 201, 151, 0.7)',  // teal
                        'rgba(13, 202, 240, 0.7)',  // info
                        'rgba(255, 193, 7, 0.7)',   // warning
                        'rgba(253, 126, 20, 0.7)',  // orange
                        'rgba(220, 53, 69, 0.7)',   // danger
                        'rgba(111, 66, 193, 0.7)',  // purple
                        'rgba(108, 117, 125, 0.7)'  // secondary
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
    
    // Resolution status chart
    const resolutionCtx = document.getElementById('resolution-chart');
    if (resolutionCtx) {
        resolutionChart = new Chart(resolutionCtx, {
            type: 'pie',
            data: {
                labels: ['Resolved', 'Unresolved'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: [
                        'rgba(25, 135, 84, 0.7)',  // success
                        'rgba(108, 117, 125, 0.7)' // secondary
                    ],
                    borderColor: [
                        'rgba(25, 135, 84, 1)',
                        'rgba(108, 117, 125, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
}

// Start anomaly detection
function startAnomalyDetection() {
    const methodEl = document.getElementById('detection-method');
    const sensitivityEl = document.getElementById('detection-sensitivity');
    
    const method = methodEl ? methodEl.value : 'statistical';
    const sensitivity = sensitivityEl ? parseFloat(sensitivityEl.value) : 3.0;
    
    // Validate input
    if (isNaN(sensitivity) || sensitivity <= 0) {
        showAlert('Please enter a valid sensitivity value (greater than 0)', 'danger');
        return;
    }
    
    // Show loading state
    const startButton = document.querySelector('#start-detection-form button[type="submit"]');
    const originalButtonText = startButton.innerHTML;
    startButton.disabled = true;
    startButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Send request to start detection
    fetch('/api/anomaly-detection/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            method: method,
            sensitivity: sensitivity
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert(`Anomaly detection started successfully using ${method} method`, 'success');
            
            // Update detection status
            updateDetectionStatus(true);
            
            // Close modal if it exists
            const modal = bootstrap.Modal.getInstance(document.getElementById('start-detection-modal'));
            if (modal) {
                modal.hide();
            }
        } else {
            throw new Error(result.error || 'Failed to start anomaly detection');
        }
    })
    .catch(error => {
        console.error('Error starting anomaly detection:', error);
        showAlert(`Error starting anomaly detection: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        startButton.disabled = false;
        startButton.innerHTML = originalButtonText;
    });
}

// Stop anomaly detection
function stopAnomalyDetection() {
    // Confirm before stopping
    if (!confirm('Are you sure you want to stop anomaly detection?')) {
        return;
    }
    
    // Show loading state
    const stopButton = document.getElementById('stop-detection');
    const originalButtonText = stopButton.innerHTML;
    stopButton.disabled = true;
    stopButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Stopping...';
    
    // Send request to stop detection
    fetch('/api/anomaly-detection/stop', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert('Anomaly detection stopped successfully', 'success');
            
            // Update detection status
            updateDetectionStatus(false);
        } else {
            throw new Error(result.error || 'Failed to stop anomaly detection');
        }
    })
    .catch(error => {
        console.error('Error stopping anomaly detection:', error);
        showAlert(`Error stopping anomaly detection: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        stopButton.disabled = false;
        stopButton.innerHTML = originalButtonText;
    });
}

// Load anomalies data
function loadAnomalies(page = 1) {
    const anomaliesTableBody = document.getElementById('anomalies-table-body');
    const paginationInfo = document.getElementById('pagination-info');
    
    if (!anomaliesTableBody) return;
    
    // Show loading state
    anomaliesTableBody.innerHTML = '<tr><td colspan="7" class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Loading anomalies...</td></tr>';
    
    // Build query parameters from filter form
    const params = new URLSearchParams();
    params.append('page', page);
    params.append('per_page', 10);
    
    // Add filter parameters
    const severityFilter = document.getElementById('filter-severity');
    const resolvedFilter = document.getElementById('filter-resolved');
    const startTimeFilter = document.getElementById('filter-start-time');
    const endTimeFilter = document.getElementById('filter-end-time');
    
    if (severityFilter && severityFilter.value) {
        params.append('severity', severityFilter.value);
    }
    
    if (resolvedFilter && resolvedFilter.value) {
        params.append('resolved', resolvedFilter.value);
    }
    
    if (startTimeFilter && startTimeFilter.value) {
        params.append('start_time', new Date(startTimeFilter.value).toISOString());
    }
    
    if (endTimeFilter && endTimeFilter.value) {
        params.append('end_time', new Date(endTimeFilter.value).toISOString());
    }
    
    // Fetch anomalies from API
    fetch(`/api/anomaly-detection/anomalies?${params.toString()}`)
        .then(response => response.json())
        .then(data => {
            // Update pagination info
            currentPage = data.current_page;
            totalPages = data.pages;
            
            if (paginationInfo) {
                paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${data.total} anomalies)`;
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
            anomaliesTableBody.innerHTML = '';
            
            // Add anomaly rows
            if (data.anomalies && data.anomalies.length > 0) {
                data.anomalies.forEach(anomaly => {
                    const row = document.createElement('tr');
                    row.className = `severity-${anomaly.severity}`;
                    
                    // Format timestamp
                    const timestamp = new Date(anomaly.timestamp);
                    const timeStr = timestamp.toLocaleString();
                    
                    // Determine severity icon/label
                    let severityIcon = 'info-circle';
                    let severityLabel = 'Info';
                    let severityClass = 'info';
                    
                    if (anomaly.severity === 2) {
                        severityIcon = 'exclamation-circle';
                        severityLabel = 'Low';
                        severityClass = 'success';
                    } else if (anomaly.severity === 3) {
                        severityIcon = 'exclamation-triangle';
                        severityLabel = 'Medium';
                        severityClass = 'warning';
                    } else if (anomaly.severity === 4) {
                        severityIcon = 'exclamation-triangle';
                        severityLabel = 'High';
                        severityClass = 'orange';
                    } else if (anomaly.severity === 5) {
                        severityIcon = 'radiation';
                        severityLabel = 'Critical';
                        severityClass = 'danger';
                    }
                    
                    row.innerHTML = `
                        <td>${timeStr}</td>
                        <td>${anomaly.event_type}</td>
                        <td><span class="badge bg-${severityClass}"><i class="fas fa-${severityIcon} me-1"></i> ${severityLabel}</span></td>
                        <td>${anomaly.description}</td>
                        <td>${anomaly.source_ip || '-'}</td>
                        <td>${anomaly.destination_ip || '-'}</td>
                        <td>
                            ${anomaly.resolved 
                                ? '<span class="badge bg-success">Resolved</span>' 
                                : `<button class="btn btn-sm btn-outline-primary resolve-anomaly" data-anomaly-id="${anomaly.id}">Resolve</button>`
                            }
                        </td>
                    `;
                    
                    anomaliesTableBody.appendChild(row);
                });
                
                // Add event listeners for resolve buttons
                document.querySelectorAll('.resolve-anomaly').forEach(button => {
                    button.addEventListener('click', function() {
                        const anomalyId = this.getAttribute('data-anomaly-id');
                        showResolveModal(anomalyId);
                    });
                });
            } else {
                // No anomalies found
                anomaliesTableBody.innerHTML = '<tr><td colspan="7" class="text-center">No anomalies found</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error loading anomalies:', error);
            anomaliesTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error loading anomalies: ${error.message}</td></tr>`;
        });
}

// Show resolve anomaly modal
function showResolveModal(anomalyId) {
    // Create modal if it doesn't exist
    let modalEl = document.getElementById('resolve-anomaly-modal');
    
    if (!modalEl) {
        modalEl = document.createElement('div');
        modalEl.id = 'resolve-anomaly-modal';
        modalEl.className = 'modal fade';
        modalEl.tabIndex = '-1';
        modalEl.setAttribute('aria-hidden', 'true');
        
        modalEl.innerHTML = 
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Resolve Anomaly</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form id="resolve-anomaly-form">
                            <input type="hidden" id="resolve-anomaly-id">
                            <div class="mb-3">
                                <label for="resolution-notes" class="form-label">Resolution Notes</label>
                                <textarea class="form-control" id="resolution-notes" rows="3" placeholder="Enter notes about how this anomaly was resolved..."></textarea>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="submit-resolve">Resolve</button>
                    </div>
                </div>
            </div>
        ;
        
        document.body.appendChild(modalEl);
        
        // Add event listener for submit button
        document.getElementById('submit-resolve').addEventListener('click', function() {
            resolveAnomaly();
        });
        
    }
    
    // Set anomaly ID in form
    document.getElementById('resolve-anomaly-id').value = anomalyId;
    
    // Clear previous notes
    document.getElementById('resolution-notes').value = '';
    
    // Show modal
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
}

// Resolve an anomaly
function resolveAnomaly() {
    const anomalyId = document.getElementById('resolve-anomaly-id').value;
    const notes = document.getElementById('resolution-notes').value;
    
    // Show loading state
    const submitButton = document.getElementById('submit-resolve');
    const originalButtonText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Resolving...';
    
    // Send request to resolve anomaly
    fetch(`/api/anomaly-detection/resolve/${anomalyId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            resolution_notes: notes
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert('Anomaly resolved successfully', 'success');
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('resolve-anomaly-modal'));
            modal.hide();
            
            // Reload anomalies
            loadAnomalies(currentPage);
            
            // Reload statistics
            loadAnomalyStatistics();
        } else {
            throw new Error(result.error || 'Failed to resolve anomaly');
        }
    })
    .catch(error => {
        console.error('Error resolving anomaly:', error);
        showAlert(`Error resolving anomaly: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        submitButton.disabled = false;
        submitButton.innerHTML = originalButtonText;
    });
}

// Load anomaly statistics
function loadAnomalyStatistics() {
    const statsContainer = document.getElementById('anomaly-statistics');
    
    if (!statsContainer) return;
    
    // Show loading state
    statsContainer.innerHTML = '<div class="text-center p-3"><div class="spinner-border" role="status"></div><p>Loading statistics...</p></div>';
    
    // Fetch statistics from API
    fetch('/api/anomaly-detection/statistics')
        .then(response => response.json())
        .then(data => {
            updateAnomalyCharts(data);
            
            // Update summary numbers
            const totalEl = document.getElementById('total-anomalies');
            const unresolvedEl = document.getElementById('unresolved-anomalies');
            const highSeverityEl = document.getElementById('high-severity-anomalies');
            
            if (totalEl) {
                totalEl.textContent = data.total;
            }
            
            if (unresolvedEl) {
                unresolvedEl.textContent = data.by_resolution.unresolved;
            }
            
            if (highSeverityEl) {
                // Count anomalies with severity 4-5
                const highSeverity = data.by_severity
                    .filter(s => s.severity >= 4)
                    .reduce((sum, s) => sum + s.count, 0);
                
                highSeverityEl.textContent = highSeverity;
            }
            
            // Restore the container
            statsContainer.innerHTML = '';
            
            // Create charts container if needed
            let chartsContainer = document.getElementById('anomaly-charts-container');
            if (!chartsContainer) {
                chartsContainer = document.createElement('div');
                chartsContainer.id = 'anomaly-charts-container';
                chartsContainer.className = 'row';
                
                chartsContainer.innerHTML = `
                    <div class="col-md-4">
                        <div class="chart-container">
                            <canvas id="severity-chart"></canvas>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="chart-container">
                            <canvas id="event-type-chart"></canvas>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="chart-container">
                            <canvas id="resolution-chart"></canvas>
                        </div>
                    </div>
                `;
                
                statsContainer.appendChild(chartsContainer);
                
                // Re-initialize charts
                initCharts();
                updateAnomalyCharts(data);
            }
        })
        .catch(error => {
            console.error('Error loading anomaly statistics:', error);
            statsContainer.innerHTML = `<div class="alert alert-danger">Error loading anomaly statistics: ${error.message}</div>`;
        });
}

// Update anomaly charts with data
function updateAnomalyCharts(data) {
    // Update severity chart
    if (severityChart) {
        // Create array with zeros for each severity level (1-5)
        const severityCounts = [0, 0, 0, 0, 0];
        
        // Fill in actual counts
        data.by_severity.forEach(item => {
            if (item.severity >= 1 && item.severity <= 5) {
                severityCounts[item.severity - 1] = item.count;
            }
        });
        
        severityChart.data.datasets[0].data = severityCounts;
        severityChart.update();
    }
    
    // Update event type chart
    if (eventTypeChart) {
        const eventTypes = data.by_event_type.map(item => item.event_type);
        const eventCounts = data.by_event_type.map(item => item.count);
        
        eventTypeChart.data.labels = eventTypes;
        eventTypeChart.data.datasets[0].data = eventCounts;
        eventTypeChart.update();
    }
    
    // Update resolution chart
    if (resolutionChart) {
        const resolvedCount = data.by_resolution.resolved || 0;
        const unresolvedCount = data.by_resolution.unresolved || 0;
        
        resolutionChart.data.datasets[0].data = [resolvedCount, unresolvedCount];
        resolutionChart.update();
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
