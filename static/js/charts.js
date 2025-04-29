// Common charts utility functions for Network Traffic Analysis Tool

// Global chart configuration
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
Chart.defaults.color = '#adb5bd';
Chart.defaults.borderColor = 'rgba(52, 58, 64, 0.1)';

// Chart color schemes
const chartColors = {
    primary: '#0d6efd',
    secondary: '#6c757d',
    success: '#198754',
    danger: '#dc3545',
    warning: '#ffc107',
    info: '#0dcaf0',
    light: '#f8f9fa',
    dark: '#212529',
    teal: '#20c997',
    purple: '#6f42c1',
    pink: '#d63384',
    orange: '#fd7e14',
    cyan: '#0dcaf0'
};

// Chart background colors with transparency
const chartBackgroundColors = {
    primary: 'rgba(13, 110, 253, 0.2)',
    secondary: 'rgba(108, 117, 125, 0.2)',
    success: 'rgba(25, 135, 84, 0.2)',
    danger: 'rgba(220, 53, 69, 0.2)',
    warning: 'rgba(255, 193, 7, 0.2)',
    info: 'rgba(13, 202, 240, 0.2)',
    light: 'rgba(248, 249, 250, 0.2)',
    dark: 'rgba(33, 37, 41, 0.2)',
    teal: 'rgba(32, 201, 151, 0.2)',
    purple: 'rgba(111, 66, 193, 0.2)',
    pink: 'rgba(214, 51, 132, 0.2)',
    orange: 'rgba(253, 126, 20, 0.2)',
    cyan: 'rgba(13, 202, 240, 0.2)'
};

// Common chart options
const commonChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
        duration: 1000
    },
    plugins: {
        legend: {
            labels: {
                boxWidth: 12,
                padding: 20
            }
        },
        tooltip: {
            cornerRadius: 4,
            caretSize: 6,
            padding: 10,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            titleFont: {
                weight: 'bold'
            }
        }
    }
};

// Create a predefined set of colors for datasets
function getChartColorScheme(index, alpha = 1) {
    const schemes = [
        `rgba(13, 110, 253, ${alpha})`,  // primary
        `rgba(32, 201, 151, ${alpha})`,  // teal
        `rgba(13, 202, 240, ${alpha})`,  // info
        `rgba(255, 193, 7, ${alpha})`,   // warning
        `rgba(253, 126, 20, ${alpha})`,  // orange
        `rgba(220, 53, 69, ${alpha})`,   // danger
        `rgba(111, 66, 193, ${alpha})`,  // purple
        `rgba(108, 117, 125, ${alpha})`, // secondary
        `rgba(25, 135, 84, ${alpha})`,   // success
        `rgba(52, 58, 64, ${alpha})`     // dark
    ];
    
    return schemes[index % schemes.length];
}

// Create a network traffic line chart
function createTrafficLineChart(ctx, options = {}) {
    const defaultOptions = {
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
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: mergedOptions
    });
}

// Create a protocol distribution pie/doughnut chart
function createProtocolChart(ctx, type = 'doughnut', options = {}) {
    const defaultOptions = {
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
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    return new Chart(ctx, {
        type: type,
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    getChartColorScheme(0, 0.7),
                    getChartColorScheme(1, 0.7),
                    getChartColorScheme(2, 0.7),
                    getChartColorScheme(3, 0.7),
                    getChartColorScheme(4, 0.7),
                    getChartColorScheme(5, 0.7),
                    getChartColorScheme(6, 0.7),
                    getChartColorScheme(7, 0.7),
                    getChartColorScheme(8, 0.7),
                    getChartColorScheme(9, 0.7)
                ],
                borderWidth: 1
            }]
        },
        options: mergedOptions
    });
}

// Create a bar chart
function createBarChart(ctx, horizontal = false, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: horizontal ? 'y' : 'x',
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
            },
            y: {
                beginAtZero: true,
                ticks: {
                    precision: 0
                }
            }
        }
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '',
                data: [],
                backgroundColor: getChartColorScheme(0, 0.7),
                borderColor: getChartColorScheme(0, 1),
                borderWidth: 1
            }]
        },
        options: mergedOptions
    });
}

// Create a multi-line time series chart for protocols
function createTimeSeriesChart(ctx, options = {}) {
    const defaultOptions = {
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
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: mergedOptions
    });
}

// Create a network map using D3.js
function createNetworkMap(selector, data) {
    const container = d3.select(selector);
    const width = container.node().getBoundingClientRect().width;
    const height = 500;
    
    // Clear previous visualization
    container.selectAll("*").remove();
    
    // Create SVG
    const svg = container.append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height])
        .attr("style", "max-width: 100%; height: auto;");
    
    // Create force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(30));
    
    // Create links
    const link = svg.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", "#999")
        .attr("stroke-opacity", 0.6)
        .attr("stroke-width", d => Math.sqrt(d.value));
    
    // Create nodes
    const node = svg.append("g")
        .selectAll("g")
        .data(data.nodes)
        .join("g")
        .call(drag(simulation));
    
    // Add circles to nodes
    node.append("circle")
        .attr("r", d => d.size || 10)
        .attr("fill", d => d.color || getChartColorScheme(d.group || 0))
        .attr("stroke", "#fff")
        .attr("stroke-width", 1.5);
    
    // Add labels to nodes
    node.append("text")
        .attr("x", 0)
        .attr("y", d => (d.size || 10) + 10)
        .attr("text-anchor", "middle")
        .attr("font-size", "10px")
        .text(d => d.id)
        .attr("fill", "#fff");
    
    // Add titles for tooltips
    node.append("title")
        .text(d => d.id);
    
    // Update positions on simulation tick
    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
        
        node.attr("transform", d => `translate(${d.x},${d.y})`);
    });
    
    // Drag functionality
    function drag(simulation) {
        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }
        
        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }
        
        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }
        
        return d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended);
    }
    
    return simulation;
}

// Update network map with new data
function updateNetworkMap(selector, simulation, data) {
    // Stop existing simulation
    if (simulation) {
        simulation.stop();
    }
    
    // Create new network map
    return createNetworkMap(selector, data);
}

// Create a heat map for network traffic
function createHeatMap(selector, data) {
    const container = d3.select(selector);
    const margin = {top: 30, right: 30, bottom: 70, left: 70};
    const width = container.node().getBoundingClientRect().width - margin.left - margin.right;
    const height = 400 - margin.top - margin.bottom;
    
    // Clear previous visualization
    container.selectAll("*").remove();
    
    // Create SVG
    const svg = container.append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", `translate(${margin.left}, ${margin.top})`);
    
    // Extract unique x and y values
    const xValues = Array.from(new Set(data.map(d => d.x)));
    const yValues = Array.from(new Set(data.map(d => d.y)));
    
    // Create scales
    const x = d3.scaleBand()
        .domain(xValues)
        .range([0, width])
        .padding(0.05);
    
    const y = d3.scaleBand()
        .domain(yValues)
        .range([height, 0])
        .padding(0.05);
    
    // Add X axis
    svg.append("g")
        .attr("transform", `translate(0, ${height})`)
        .call(d3.axisBottom(x).tickSize(0))
        .selectAll("text")
        .style("text-anchor", "end")
        .attr("transform", "rotate(-45)")
        .attr("dx", "-.8em")
        .attr("dy", ".15em");
    
    // Add Y axis
    svg.append("g")
        .call(d3.axisLeft(y).tickSize(0));
    
    // Color scale
    const colorScale = d3.scaleSequential()
        .interpolator(d3.interpolateInferno)
        .domain([0, d3.max(data, d => d.value)]);
    
    // Create tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "chart-tooltip")
        .style("opacity", 0)
        .style("position", "absolute");
    
    // Add squares
    svg.selectAll()
        .data(data)
        .enter()
        .append("rect")
        .attr("x", d => x(d.x))
        .attr("y", d => y(d.y))
        .attr("width", x.bandwidth())
        .attr("height", y.bandwidth())
        .style("fill", d => colorScale(d.value))
        .on("mouseover", function(event, d) {
            tooltip.transition()
                .duration(200)
                .style("opacity", .9);
            tooltip.html(`${d.x}, ${d.y}<br/>${formatBytes(d.value)}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        });
}
