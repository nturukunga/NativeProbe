// Packet Analysis JavaScript for Network Traffic Analysis Tool

// Global variables
let packetsTable = null;
let currentCaptureId = null;
let currentPage = 1;
let totalPages = 1;
let captureIntervalId = null;

// Initialize the packet analysis page
document.addEventListener('DOMContentLoaded', function() {
    // Load capture interfaces
    loadCaptureInterfaces();
    
    // Load existing captures
    loadCaptures();
    
    // Set up event listeners
    setupEventListeners();
});

// Set up event listeners
function setupEventListeners() {
    // Start capture form submission
    const startCaptureForm = document.getElementById('start-capture-form');
    if (startCaptureForm) {
        startCaptureForm.addEventListener('submit', function(event) {
            event.preventDefault();
            startCapture();
        });
    }
    
    // Pagination controls
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', function() {
            if (currentPage > 1) {
                currentPage--;
                loadPackets(currentCaptureId, currentPage);
            }
        });
    }
    
    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', function() {
            if (currentPage < totalPages) {
                currentPage++;
                loadPackets(currentCaptureId, currentPage);
            }
        });
    }
    
    // Packet filter input
    const packetFilter = document.getElementById('packet-filter');
    if (packetFilter) {
        packetFilter.addEventListener('keyup', function(event) {
            if (event.key === 'Enter') {
                filterPackets();
            }
        });
    }
    
    // Filter button
    const filterBtn = document.getElementById('apply-filter');
    if (filterBtn) {
        filterBtn.addEventListener('click', filterPackets);
    }
    
    // Export button
    const exportBtn = document.getElementById('export-packets');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportPackets);
    }
}

// Load available capture interfaces
function loadCaptureInterfaces() {
    const interfaceSelect = document.getElementById('capture-interface');
    if (!interfaceSelect) return;
    
    // Show loading indicator
    interfaceSelect.innerHTML = '<option value="">Loading interfaces...</option>';
    
    fetch('/api/settings/interfaces')
        .then(response => response.json())
        .then(interfaces => {
            // Clear loading option
            interfaceSelect.innerHTML = '';
            
            // Add option for each interface
            interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface.name;
                option.textContent = `${iface.name}${iface.description ? ` (${iface.description})` : ''}`;
                
                // Disable if interface is down
                if (!iface.is_up) {
                    option.disabled = true;
                    option.textContent += ' [DOWN]';
                }
                
                interfaceSelect.appendChild(option);
            });
            
            // If no interfaces found
            if (interfaces.length === 0) {
                const option = document.createElement('option');
                option.value = '';
                option.textContent = 'No interfaces available';
                option.disabled = true;
                interfaceSelect.appendChild(option);
            }
        })
        .catch(error => {
            console.error('Error loading interfaces:', error);
            interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        });
}

// Load existing packet captures
function loadCaptures() {
    const capturesContainer = document.getElementById('captures-list');
    if (!capturesContainer) return;
    
    // Show loading
    capturesContainer.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Loading captures...</div>';
    
    fetch('/api/packet-analysis/captures')
        .then(response => response.json())
        .then(captures => {
            // Clear loading
            capturesContainer.innerHTML = '';
            
            if (captures.length > 0) {
                // Create a list group
                const listGroup = document.createElement('div');
                listGroup.className = 'list-group';
                
                // Add each capture as a list item
                captures.forEach(capture => {
                    const listItem = document.createElement('a');
                    listItem.href = '#';
                    listItem.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
                    listItem.setAttribute('data-capture-id', capture.id);
                    
                    // Format times
                    const startTime = new Date(capture.start_time).toLocaleString();
                    const endTime = capture.end_time ? new Date(capture.end_time).toLocaleString() : 'Active';
                    
                    // Determine status badges
                    let statusBadge = '';
                    if (capture.active) {
                        statusBadge = '<span class="badge bg-success ms-2">Active</span>';
                    } else {
                        statusBadge = '<span class="badge bg-secondary ms-2">Completed</span>';
                    }
                    
                    listItem.innerHTML = `
                        <div>
                            <div class="fw-bold">${capture.name} ${statusBadge}</div>
                            <small>Interface: ${capture.interface} | Start: ${startTime} | End: ${endTime}</small>
                            <div>Packets: ${capture.packet_count.toLocaleString()}</div>
                            ${capture.filter_expression ? `<div class="text-muted small">Filter: ${capture.filter_expression}</div>` : ''}
                        </div>
                        <div>
                            <button class="btn btn-sm btn-primary view-packets" title="View Packets">
                                <i class="fas fa-eye"></i>
                            </button>
                            ${capture.active ? `
                                <button class="btn btn-sm btn-danger stop-capture" title="Stop Capture">
                                    <i class="fas fa-stop"></i>
                                </button>
                            ` : ''}
                        </div>
                    `;
                    
                    listGroup.appendChild(listItem);
                });
                
                capturesContainer.appendChild(listGroup);
                
                // Add event listeners for action buttons
                document.querySelectorAll('.view-packets').forEach(button => {
                    button.addEventListener('click', function(event) {
                        event.preventDefault();
                        const captureId = this.closest('.list-group-item').getAttribute('data-capture-id');
                        viewCapture(captureId);
                    });
                });
                
                document.querySelectorAll('.stop-capture').forEach(button => {
                    button.addEventListener('click', function(event) {
                        event.preventDefault();
                        const captureId = this.closest('.list-group-item').getAttribute('data-capture-id');
                        stopCapture(captureId);
                    });
                });
                
                // Also make the whole item clickable to view packets
                document.querySelectorAll('.list-group-item').forEach(item => {
                    item.addEventListener('click', function(event) {
                        // Only handle if the click wasn't on a button
                        if (!event.target.closest('button')) {
                            event.preventDefault();
                            const captureId = this.getAttribute('data-capture-id');
                            viewCapture(captureId);
                        }
                    });
                });
            } else {
                // No captures yet
                capturesContainer.innerHTML = '<div class="alert alert-info">No packet captures found. Start a new capture to begin.</div>';
            }
        })
        .catch(error => {
            console.error('Error loading captures:', error);
            capturesContainer.innerHTML = `<div class="alert alert-danger">Error loading captures: ${error.message}</div>`;
        });
}

// Start a new packet capture
function startCapture() {
    // Get form data
    const interfaceEl = document.getElementById('capture-interface');
    const nameEl = document.getElementById('capture-name');
    const filterEl = document.getElementById('capture-filter');
    const timeoutEl = document.getElementById('capture-timeout');
    
    const interface = interfaceEl.value;
    const name = nameEl.value;
    const filter = filterEl.value;
    const timeout = parseInt(timeoutEl.value);
    
    // Validate form
    if (!interface) {
        showAlert('Please select a capture interface', 'danger');
        return;
    }
    
    if (!name) {
        showAlert('Please enter a name for the capture', 'danger');
        return;
    }
    
    // Prepare data
    const data = {
        interface: interface,
        name: name,
        filter_expression: filter,
        timeout: timeout
    };
    
    // Show loading state
    const startButton = document.querySelector('#start-capture-form button[type="submit"]');
    const originalButtonText = startButton.innerHTML;
    startButton.disabled = true;
    startButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting...';
    
    // Send request to start capture
    fetch('/api/packet-analysis/start-capture', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Show success message
            showAlert(`Capture "${name}" started successfully`, 'success');
            
            // Reset form
            nameEl.value = '';
            filterEl.value = '';
            
            // Reload captures list
            loadCaptures();
            
            // Automatically view the new capture
            setTimeout(() => viewCapture(result.capture_id), 1000);
            
            // Close modal if it exists
            const modal = bootstrap.Modal.getInstance(document.getElementById('start-capture-modal'));
            if (modal) {
                modal.hide();
            }
        } else {
            throw new Error(result.error || 'Failed to start capture');
        }
    })
    .catch(error => {
        console.error('Error starting capture:', error);
        showAlert(`Error starting capture: ${error.message}`, 'danger');
    })
    .finally(() => {
        // Reset button state
        startButton.disabled = false;
        startButton.innerHTML = originalButtonText;
    });
}

// Stop an active packet capture
function stopCapture(captureId) {
    // Confirm before stopping
    if (!confirm('Are you sure you want to stop this capture?')) {
        return;
    }
    
    fetch(`/api/packet-analysis/stop-capture/${captureId}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            showAlert('Capture stopped successfully', 'success');
            
            // Reload captures
            loadCaptures();
            
            // If we're viewing this capture, reload packets
            if (currentCaptureId === captureId) {
                loadPackets(captureId);
            }
        } else {
            throw new Error(result.error || 'Failed to stop capture');
        }
    })
    .catch(error => {
        console.error('Error stopping capture:', error);
        showAlert(`Error stopping capture: ${error.message}`, 'danger');
    });
}

// View a specific capture's packets
function viewCapture(captureId) {
    // Store the current capture ID
    currentCaptureId = captureId;
    currentPage = 1;
    
    // Show packets container
    const packetsContainer = document.getElementById('packets-container');
    if (packetsContainer) {
        packetsContainer.style.display = 'block';
    }
    
    // Set active capture in UI
    const captureItems = document.querySelectorAll('.list-group-item');
    captureItems.forEach(item => {
        if (item.getAttribute('data-capture-id') === captureId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
    
    // Load packets
    loadPackets(captureId);
    
    // If the capture is active, set up auto-refresh
    const isActive = document.querySelector(`.list-group-item[data-capture-id="${captureId}"] .badge.bg-success`) !== null;
    
    if (isActive) {
        // Clear existing interval
        if (captureIntervalId) {
            clearInterval(captureIntervalId);
        }
        
        // Set new interval
        captureIntervalId = setInterval(() => {
            loadPackets(captureId, currentPage);
        }, 5000); // Refresh every 5 seconds
    } else {
        // Clear interval if capture is not active
        if (captureIntervalId) {
            clearInterval(captureIntervalId);
            captureIntervalId = null;
        }
    }
}

// Load packets for a specific capture
function loadPackets(captureId, page = 1) {
    const packetsTable = document.getElementById('packets-table-body');
    const paginationInfo = document.getElementById('pagination-info');
    
    if (!packetsTable) return;
    
    // Show loading state
    packetsTable.innerHTML = '<tr><td colspan="7" class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Loading packets...</td></tr>';
    
    // Fetch packets from API
    fetch(`/api/packet-analysis/packets/${captureId}?page=${page}&per_page=50`)
        .then(response => response.json())
        .then(data => {
            // Update pagination info
            currentPage = data.current_page;
            totalPages = data.pages;
            
            if (paginationInfo) {
                paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${data.total} packets)`;
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
            packetsTable.innerHTML = '';
            
            // Add packet rows
            if (data.packets && data.packets.length > 0) {
                data.packets.forEach((packet, index) => {
                    const row = document.createElement('tr');
                    row.className = 'packet-row';
                    row.setAttribute('data-packet-id', packet.id);
                    
                    // Format timestamp
                    const timestamp = new Date(packet.timestamp);
                    const timeStr = timestamp.toLocaleTimeString() + '.' + String(timestamp.getMilliseconds()).padStart(3, '0');
                    
                    // Format protocol
                    let protocolClass = '';
                    if (packet.protocol) {
                        protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
                    }
                    
                    // Format TCP flags if present
                    let flagsHtml = '';
                    if (packet.tcp_flags) {
                        flagsHtml = '<span class="tcp-flags">';
                        for (let i = 0; i < packet.tcp_flags.length; i++) {
                            flagsHtml += `<span class="flag-${packet.tcp_flags[i]}">${packet.tcp_flags[i]}</span>`;
                        }
                        flagsHtml += '</span>';
                    }
                    
                    row.innerHTML = `
                        <td>${index + 1 + (currentPage - 1) * 50}</td>
                        <td>${timeStr}</td>
                        <td class="${protocolClass}">${packet.protocol || 'Unknown'}</td>
                        <td>${packet.source_ip || ''}${packet.source_port ? ':' + packet.source_port : ''}</td>
                        <td>${packet.destination_ip || ''}${packet.destination_port ? ':' + packet.destination_port : ''}</td>
                        <td>${packet.length || 0}</td>
                        <td>${flagsHtml}</td>
                        <td>${packet.info || ''}</td>
                    `;
                    
                    packetsTable.appendChild(row);
                });
                
                // Add click event to rows
                document.querySelectorAll('.packet-row').forEach(row => {
                    row.addEventListener('click', function() {
                        const packetId = this.getAttribute('data-packet-id');
                        showPacketDetails(packetId);
                        
                        // Highlight selected row
                        document.querySelectorAll('.packet-row').forEach(r => r.classList.remove('table-active'));
                        this.classList.add('table-active');
                    });
                });
            } else {
                // No packets found
                packetsTable.innerHTML = '<tr><td colspan="7" class="text-center">No packets found</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error loading packets:', error);
            packetsTable.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error loading packets: ${error.message}</td></tr>`;
        });
}

// Show detailed information for a specific packet
function showPacketDetails(packetId) {
    const detailsContainer = document.getElementById('packet-details');
    
    if (!detailsContainer) return;
    
    // Show loading
    detailsContainer.innerHTML = '<div class="text-center p-3"><div class="spinner-border" role="status"></div><p>Loading packet details...</p></div>';
    
    // Fetch packet details
    fetch(`/api/packet-analysis/packet-details/${packetId}`)
        .then(response => response.json())
        .then(data => {
            // Format details
            let detailsHtml = `
                <div class="packet-details">
                    <h5>Packet #${packetId}</h5>
                    <ul class="nav nav-tabs" id="packetTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="summary-tab" data-bs-toggle="tab" data-bs-target="#summary" type="button" role="tab">Summary</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="ethernet-tab" data-bs-toggle="tab" data-bs-target="#ethernet" type="button" role="tab">Ethernet</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip" type="button" role="tab">IP</button>
                        </li>`;
            
            // Add protocol-specific tabs
            if (data.details.tcp) {
                detailsHtml += `
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="tcp-tab" data-bs-toggle="tab" data-bs-target="#tcp" type="button" role="tab">TCP</button>
                    </li>`;
            } else if (data.details.udp) {
                detailsHtml += `
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="udp-tab" data-bs-toggle="tab" data-bs-target="#udp" type="button" role="tab">UDP</button>
                    </li>`;
            }
            
            detailsHtml += `
                    </ul>
                    <div class="tab-content p-3 border border-top-0 rounded-bottom" id="packetTabContent">
                        <div class="tab-pane fade show active" id="summary" role="tabpanel">
                            <table class="table table-sm">
                                <tr>
                                    <th>Timestamp</th>
                                    <td>${new Date(data.details.general.timestamp).toLocaleString()}</td>
                                </tr>
                                <tr>
                                    <th>Length</th>
                                    <td>${data.details.general.length} bytes</td>
                                </tr>
                            </table>
                        </div>
                        <div class="tab-pane fade" id="ethernet" role="tabpanel">
                            <table class="table table-sm">
                                <tr>
                                    <th>Source MAC</th>
                                    <td>${data.details.ethernet.source_mac}</td>
                                </tr>
                                <tr>
                                    <th>Destination MAC</th>
                                    <td>${data.details.ethernet.destination_mac}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="tab-pane fade" id="ip" role="tabpanel">
                            <table class="table table-sm">
                                <tr>
                                    <th>Version</th>
                                    <td>${data.details.ip.version}</td>
                                </tr>
                                <tr>
                                    <th>Header Length</th>
                                    <td>${data.details.ip.header_length} bytes</td>
                                </tr>
                                <tr>
                                    <th>Total Length</th>
                                    <td>${data.details.ip.total_length} bytes</td>
                                </tr>
                                <tr>
                                    <th>TTL</th>
                                    <td>${data.details.ip.ttl}</td>
                                </tr>
                                <tr>
                                    <th>Protocol</th>
                                    <td>${data.details.ip.protocol}</td>
                                </tr>
                                <tr>
                                    <th>Source IP</th>
                                    <td>${data.details.ip.source}</td>
                                </tr>
                                <tr>
                                    <th>Destination IP</th>
                                    <td>${data.details.ip.destination}</td>
                                </tr>
                            </table>
                        </div>`;
            
            // Add TCP details if available
            if (data.details.tcp) {
                detailsHtml += `
                    <div class="tab-pane fade" id="tcp" role="tabpanel">
                        <table class="table table-sm">
                            <tr>
                                <th>Source Port</th>
                                <td>${data.details.tcp.source_port}</td>
                            </tr>
                            <tr>
                                <th>Destination Port</th>
                                <td>${data.details.tcp.destination_port}</td>
                            </tr>
                            <tr>
                                <th>Sequence Number</th>
                                <td>${data.details.tcp.sequence_number}</td>
                            </tr>
                            <tr>
                                <th>Acknowledgment Number</th>
                                <td>${data.details.tcp.acknowledgment_number}</td>
                            </tr>
                            <tr>
                                <th>Flags</th>
                                <td class="tcp-flags">${formatTcpFlags(data.details.tcp.flags)}</td>
                            </tr>
                            <tr>
                                <th>Window Size</th>
                                <td>${data.details.tcp.window_size}</td>
                            </tr>
                        </table>
                    </div>`;
            }
            
            // Add UDP details if available
            if (data.details.udp) {
                detailsHtml += `
                    <div class="tab-pane fade" id="udp" role="tabpanel">
                        <table class="table table-sm">
                            <tr>
                                <th>Source Port</th>
                                <td>${data.details.udp.source_port}</td>
                            </tr>
                            <tr>
                                <th>Destination Port</th>
                                <td>${data.details.udp.destination_port}</td>
                            </tr>
                            <tr>
                                <th>Length</th>
                                <td>${data.details.udp.length}</td>
                            </tr>
                            <tr>
                                <th>Checksum</th>
                                <td>${data.details.udp.checksum}</td>
                            </tr>
                        </table>
                    </div>`;
            }
            
            detailsHtml += `
                    </div>
                </div>
            `;
            
            detailsContainer.innerHTML = detailsHtml;
            
            // Initialize tabs
            new bootstrap.Tab(document.getElementById('summary-tab')).show();
        })
        .catch(error => {
            console.error('Error loading packet details:', error);
            detailsContainer.innerHTML = `<div class="alert alert-danger">Error loading packet details: ${error.message}</div>`;
        });
}

// Format TCP flags for display
function formatTcpFlags(flags) {
    if (typeof flags === 'string') {
        let html = '';
        for (let i = 0; i < flags.length; i++) {
            html += `<span class="flag-${flags[i]}">${flags[i]}</span>`;
        }
        return html;
    }
    return flags;
}

// Filter packets based on search input
function filterPackets() {
    // This would typically be implemented with a backend filter
    // For now, we'll just reload the current page
    const filterInput = document.getElementById('packet-filter');
    if (filterInput && filterInput.value.trim()) {
        // Show alert that filtering is not implemented yet
        showAlert('Packet filtering is not fully implemented in this version', 'warning');
    }
    
    // Reload current packets
    if (currentCaptureId) {
        loadPackets(currentCaptureId, 1);
    }
}

// Export packets to file
function exportPackets() {
    // This would typically download a PCAP file or CSV
    // For now, just show a message
    showAlert('Export functionality is not implemented in this version', 'info');
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
