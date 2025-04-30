// Charts utility functions for Network Traffic Analysis Tool

// Load Chart.js if it's not already loaded
if (typeof Chart === 'undefined') {
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js';
    script.onload = function() {
        console.log('Chart.js loaded successfully');

        // Set default Chart.js configuration
        Chart.defaults.font.family = '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
        Chart.defaults.font.size = 12;
        Chart.defaults.plugins.tooltip.padding = 10;
        Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(0, 0, 0, 0.8)';
        Chart.defaults.plugins.legend.labels.usePointStyle = true;
    };
    document.head.appendChild(script);
} else {
    console.log('Chart.js is already loaded');
}

// Format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Format numbers to human-readable format
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    if (num < 1000) return num.toString();

    const si = [
        { value: 1E15, symbol: "P" },
        { value: 1E12, symbol: "T" },
        { value: 1E9, symbol: "G" },
        { value: 1E6, symbol: "M" },
        { value: 1E3, symbol: "k" }
    ];

    for (let i = 0; i < si.length; i++) {
        if (num >= si[i].value) {
            return (num / si[i].value).toFixed(1).replace(/\.0+$|(\.[0-9]*[1-9])0+$/, "$1") + si[i].symbol;
        }
    }

    return num.toString();
}

// Get a color from a predefined palette
function getColor(index) {
    const colors = [
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
    ];

    return colors[index % colors.length];
}

// Generate a lighter version of a color
function getLighterColor(hexColor, opacity = 0.2) {
    // Add alpha channel for transparency
    return hexColor + Math.round(opacity * 255).toString(16).padStart(2, '0');
}

// Format date for charts
function formatDate(date, format = 'time') {
    if (!(date instanceof Date)) {
        date = new Date(date);
    }

    if (format === 'time') {
        return date.toLocaleTimeString();
    } else if (format === 'date') {
        return date.toLocaleDateString();
    } else if (format === 'datetime') {
        return date.toLocaleString();
    }

    return date.toLocaleString();
}

// Create a new chart
function createChart(ctx, type, data, options) {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded');
        return null;
    }

    return new Chart(ctx, {
        type: type,
        data: data,
        options: options
    });
}

// Global chart configuration (using new formatNumber)
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
Chart.defaults.color = '#adb5bd';
Chart.defaults.borderColor = 'rgba(52, 58, 64, 0.1)';

// Chart color schemes (using getColor)
const chartColors = {
    primary: getColor(0),
    secondary: getColor(7),
    success: getColor(8),
    danger: getColor(5),
    warning: getColor(3),
    info: getColor(2),
    light: '#f8f9fa',
    dark: getColor(9),
    teal: getColor(1),
    purple: getColor(6),
    pink: '#d63384',
    orange: getColor(4),
    cyan: getColor(2)
};

// Chart background colors with transparency (using getLighterColor)
const chartBackgroundColors = {
    primary: getLighterColor(getColor(0)),
    secondary: getLighterColor(getColor(7)),
    success: getLighterColor(getColor(8)),
    danger: getLighterColor(getColor(5)),
    warning: getLighterColor(getColor(3)),
    info: getLighterColor(getColor(2)),
    light: 'rgba(248, 249, 250, 0.2)',
    dark: getLighterColor(getColor(9)),
    teal: getLighterColor(getColor(1)),
    purple: getLighterColor(getColor(6)),
    pink: 'rgba(214, 51, 132, 0.2)',
    orange: getLighterColor(getColor(4)),
    cyan: getLighterColor(getColor(2))
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

// Create a predefined set of colors for datasets (using getColor)
function getChartColorScheme(index, alpha = 1) {
    return `rgba(${getColor(index).substring(1)}, ${alpha})`;
}


// Create a network traffic line chart (using createChart and formatBytes)
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

    return createChart(ctx, 'line', {
        labels: [],
        datasets: []
    }, mergedOptions);
}

// Create a protocol distribution pie/doughnut chart (using createChart and formatBytes)
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

    return createChart(ctx, type, {
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
    }, mergedOptions);
}

// Create a bar chart (using createChart)
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

    return createChart(ctx, 'bar', {
        labels: [],
        datasets: [{
            label: '',
            data: [],
            backgroundColor: getChartColorScheme(0, 0.7),
            borderColor: getChartColorScheme(0, 1),
            borderWidth: 1
        }]
    }, mergedOptions);
}

// Create a multi-line time series chart for protocols (using createChart and formatBytes)
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

    return createChart(ctx, 'line', {
        labels: [],
        datasets: []
    }, mergedOptions);
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