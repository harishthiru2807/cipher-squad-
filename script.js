// Global state
const state = {
    threats: [],
    maliciousIPs: [],
    phishingDomains: [],
    malwareData: [],
    alerts: [],
    charts: {},
    updateInterval: null,
    currentModule: 'dashboard',
    spamChecks: [],
    chatHistory: [],
    suggestions: []
};

// Threat intelligence sources
const threatSources = [
    'Open Threat Exchange (OTX)',
    'AbuseIPDB',
    'VirusTotal Intelligence',
    'ThreatConnect',
    'Cymru IP to ASN',
    'URLhaus',
    'PhishTank'
];

const threatTypes = ['malware', 'phishing', 'malicious-ip', 'ddos', 'exploit', 'ransomware', 'trojan'];
const malwareTypes = ['ransomware', 'trojan', 'virus', 'worm', 'backdoor', 'rootkit'];
const severityLevels = ['critical', 'high', 'medium', 'low'];

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    setupNavigation();
    initializeTimeDisplay();
    generateInitialData();
    initializeCharts();
    setupEventListeners();
    startRealTimeUpdates();
}

// Navigation
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const module = item.getAttribute('data-module');
            switchModule(module);
        });
    });

    const menuToggle = document.getElementById('menuToggle');
    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            document.querySelector('.sidebar').classList.toggle('open');
        });
    }
}

function switchModule(moduleName) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-module') === moduleName) {
            item.classList.add('active');
        }
    });

    // Update module content
    document.querySelectorAll('.module-content').forEach(content => {
        content.classList.remove('active');
    });

    const targetModule = document.getElementById(`module-${moduleName}`);
    if (targetModule) {
        targetModule.classList.add('active');
    }

    // Update page title
    const titles = {
        'dashboard': 'Dashboard Overview',
        'threat-feed': 'Live Threat Feed',
        'malicious-ip': 'Malicious IP Intelligence',
        'phishing': 'Phishing and Malicious Domains',
        'malware': 'Malware Threat Intelligence',
        'analytics': 'Threat Analytics and Trends',
        'alerts': 'Alerts and Incident Management',
        'reports': 'Reports and Exports',
        'settings': 'Settings'
    };

    document.getElementById('pageTitle').textContent = titles[moduleName] || 'Dashboard';
    state.currentModule = moduleName;

    // Refresh module data
    refreshModuleData(moduleName);
}

function refreshModuleData(moduleName) {
    switch(moduleName) {
        case 'dashboard':
            updateDashboardMetrics();
            updateRecentThreats();
            break;
        case 'threat-feed':
            renderThreatFeed();
            break;
        case 'malicious-ip':
            renderMaliciousIPs();
            break;
        case 'phishing':
            renderPhishingDomains();
            break;
        case 'malware':
            renderMalwareIntel();
            break;
        case 'analytics':
            updateAnalyticsCharts();
            break;
        case 'alerts':
            renderAlerts();
            break;
        case 'reports':
            renderRecentReports();
            break;
    }
}

// Time display
function initializeTimeDisplay() {
    updateTime();
    setInterval(updateTime, 1000);
}

function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const dateString = now.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric'
    });
    document.getElementById('timeDisplay').textContent = `${dateString} ${timeString}`;
}

// Data generation
function generateInitialData() {
    // Generate threats
    for (let i = 0; i < 50; i++) {
        state.threats.push(generateThreat());
    }

    // Generate malicious IPs
    for (let i = 0; i < 30; i++) {
        state.maliciousIPs.push(generateMaliciousIP());
    }

    // Generate phishing domains
    for (let i = 0; i < 25; i++) {
        state.phishingDomains.push(generatePhishingDomain());
    }

    // Generate malware data
    for (let i = 0; i < 20; i++) {
        state.malwareData.push(generateMalwareSample());
    }

    // Generate alerts
    for (let i = 0; i < 15; i++) {
        state.alerts.push(generateAlert());
    }

    // Sort by timestamp (newest first)
    state.threats.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    state.alerts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function generateThreat() {
    const types = ['malware', 'phishing', 'malicious-ip', 'ddos', 'exploit'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const type = types[Math.floor(Math.random() * types.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const source = threatSources[Math.floor(Math.random() * threatSources.length)];
    
    const descriptions = {
        'malware': ['Suspicious executable detected', 'Trojan downloader identified', 'Ransomware variant discovered'],
        'phishing': ['Phishing campaign targeting financial institutions', 'Suspicious email campaign detected', 'Credential harvesting attempt'],
        'malicious-ip': ['Known botnet C&C server', 'Malicious IP scanning for vulnerabilities', 'Suspected APT infrastructure'],
        'ddos': ['Large-scale DDoS attack detected', 'Volumetric attack in progress', 'Application layer attack'],
        'exploit': ['Zero-day exploit attempt', 'Known CVE exploitation', 'SQL injection attempt']
    };

    const titles = {
        'malware': ['Trojan.Win32.Generic', 'Ransomware.CryptoWall', 'Backdoor.Linux.EggShell'],
        'phishing': ['Phishing Campaign: Financial Services', 'Credential Harvesting Attempt', 'Suspicious Email Campaign'],
        'malicious-ip': ['Malicious IP: 192.168.1.100', 'Botnet C&C Server Detected', 'APT Infrastructure IP'],
        'ddos': ['DDoS Attack on Port 443', 'Large-scale Volumetric Attack', 'Application Layer DDoS'],
        'exploit': ['CVE-2023-XXXX Exploitation', 'Zero-day Exploit Attempt', 'SQL Injection Attack']
    };

    return {
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        title: titles[type][Math.floor(Math.random() * titles[type].length)],
        type: type,
        severity: severity,
        description: descriptions[type][Math.floor(Math.random() * descriptions[type].length)],
        source: source,
        timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
        ipAddress: generateRandomIP(),
        indicator: generateRandomHash()
    };
}

function generateMaliciousIP() {
    const severities = ['critical', 'high', 'medium', 'low'];
    const types = ['Botnet', 'C&C Server', 'Malware Distribution', 'Scanning Activity', 'APT Infrastructure'];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    
    const riskScores = {
        'critical': [90, 95, 98, 100],
        'high': [70, 75, 80, 85],
        'medium': [50, 55, 60, 65],
        'low': [30, 35, 40, 45]
    };

    return {
        id: `ip-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        ip: generateRandomIP(),
        reputationScore: riskScores[severity][Math.floor(Math.random() * riskScores[severity].length)],
        riskLevel: severity,
        threatType: types[Math.floor(Math.random() * types.length)],
        firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
        source: threatSources[Math.floor(Math.random() * threatSources.length)]
    };
}

function generatePhishingDomain() {
    const domains = [
        'paypal-security.com', 'microsoft-verify.net', 'apple-support.org',
        'amazon-update.com', 'google-account.net', 'bank-verify.org',
        'secure-login.net', 'update-required.com', 'suspicious-site.org'
    ];
    
    const types = ['phishing', 'malware', 'spam', 'botnet'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const type = types[Math.floor(Math.random() * types.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];

    const riskScores = {
        'critical': [90, 95, 98, 100],
        'high': [70, 75, 80, 85],
        'medium': [50, 55, 60, 65],
        'low': [30, 35, 40, 45]
    };

    return {
        id: `domain-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        domain: domains[Math.floor(Math.random() * domains.length)],
        threatType: type,
        riskScore: riskScores[severity][Math.floor(Math.random() * riskScores[severity].length)],
        registrationDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
        firstDetected: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        status: Math.random() > 0.5 ? 'Active' : 'Inactive',
        source: threatSources[Math.floor(Math.random() * threatSources.length)]
    };
}

function generateMalwareSample() {
    const names = [
        'Trojan.Generic.123456',
        'Ransomware.WannaCry.Variant',
        'Backdoor.Linux.Rootkit',
        'Virus.Win32.Sality',
        'Worm.MSIL.Autorun',
        'Trojan.Android.Banker'
    ];
    
    const types = ['ransomware', 'trojan', 'virus', 'worm', 'backdoor', 'rootkit'];
    const severities = ['critical', 'high', 'medium', 'low'];
    const type = types[Math.floor(Math.random() * types.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];

    const descriptions = [
        'Malicious software designed to encrypt files and demand ransom',
        'Trojan horse that appears legitimate but performs malicious actions',
        'Self-replicating malware that spreads across networks',
        'Stealthy malware that hides its presence on the system',
        'Software that provides unauthorized remote access',
        'Low-level malware that modifies system kernel'
    ];

    return {
        id: `malware-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        name: names[Math.floor(Math.random() * names.length)],
        type: type,
        severity: severity,
        hash: generateRandomHash(),
        firstSeen: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000),
        detections: Math.floor(Math.random() * 5000) + 100,
        description: descriptions[Math.floor(Math.random() * descriptions.length)]
    };
}

function generateAlert() {
    const severities = ['critical', 'high', 'medium', 'low'];
    const statuses = ['new', 'investigating', 'resolved', 'false-positive'];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];

    const titles = [
        'Critical Threat Detected',
        'Suspicious Network Activity',
        'Malware Infection Attempt',
        'Phishing Campaign Alert',
        'APT Attack Indicators',
        'Data Exfiltration Attempt'
    ];

    return {
        id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        title: titles[Math.floor(Math.random() * titles.length)],
        severity: severity,
        status: status,
        description: 'Automated threat intelligence system has detected suspicious activity matching known attack patterns.',
        source: threatSources[Math.floor(Math.random() * threatSources.length)],
        createdAt: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
        indicator: generateRandomIP(),
        affectedSystems: Math.floor(Math.random() * 50) + 1
    };
}

function generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function generateRandomHash() {
    const chars = '0123456789abcdef';
    let hash = '';
    for (let i = 0; i < 64; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

// Charts initialization
function initializeCharts() {
    createThreatTrendsChart();
    createThreatDistributionChart();
    createAttackPatternsChart();
    createTopSourcesChart();
    createAnalyticsTimelineChart();
    createGeographicChart();
    createAttackVectorChart();
}

function createThreatTrendsChart() {
    const ctx = document.getElementById('threatTrendsChart');
    if (!ctx) return;

    const hours = Array.from({length: 24}, (_, i) => {
        const date = new Date();
        date.setHours(date.getHours() - (23 - i));
        return date.getHours().toString().padStart(2, '0') + ':00';
    });

    const critical = Array.from({length: 24}, () => Math.floor(Math.random() * 20) + 5);
    const high = Array.from({length: 24}, () => Math.floor(Math.random() * 30) + 10);
    const medium = Array.from({length: 24}, () => Math.floor(Math.random() * 40) + 15);
    const low = Array.from({length: 24}, () => Math.floor(Math.random() * 50) + 20);

    state.charts.threatTrends = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours,
            datasets: [
                {
                    label: 'Critical',
                    data: critical,
                    borderColor: '#ff3838',
                    backgroundColor: 'rgba(255, 56, 56, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: high,
                    borderColor: '#ff6b35',
                    backgroundColor: 'rgba(255, 107, 53, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: medium,
                    borderColor: '#ffa726',
                    backgroundColor: 'rgba(255, 167, 38, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Low',
                    data: low,
                    borderColor: '#ffeb3b',
                    backgroundColor: 'rgba(255, 235, 59, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#a0aec0' }
                }
            },
            scales: {
                x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } }
            }
        }
    });
}

function createThreatDistributionChart() {
    const ctx = document.getElementById('threatDistributionChart');
    if (!ctx) return;

    state.charts.threatDistribution = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malware', 'Phishing', 'Malicious IP', 'DDoS', 'Exploit'],
            datasets: [{
                data: [35, 25, 20, 12, 8],
                backgroundColor: [
                    '#ff3838',
                    '#ff6b35',
                    '#ffa726',
                    '#ffeb3b',
                    '#00d4ff'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#a0aec0' }
                }
            }
        }
    });
}

function createAttackPatternsChart() {
    const ctx = document.getElementById('attackPatternsChart');
    if (!ctx) return;

    state.charts.attackPatterns = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Brute Force', 'SQL Injection', 'XSS', 'Ransomware', 'Phishing', 'DDoS'],
            datasets: [{
                label: 'Attack Count',
                data: [45, 32, 28, 38, 52, 25],
                backgroundColor: '#00d4ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } }
            }
        }
    });
}

function createTopSourcesChart() {
    const ctx = document.getElementById('topSourcesChart');
    if (!ctx) return;

    state.charts.topSources = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: threatSources.slice(0, 5),
            datasets: [{
                label: 'Threats',
                data: [45, 38, 32, 28, 22],
                backgroundColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#a0aec0' }, grid: { display: false } }
            }
        }
    });
}

function createAnalyticsTimelineChart() {
    const ctx = document.getElementById('analyticsTimelineChart');
    if (!ctx) return;

    const days = Array.from({length: 30}, (_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - (29 - i));
        return (date.getMonth() + 1) + '/' + date.getDate();
    });

    state.charts.analyticsTimeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: days,
            datasets: [{
                label: 'Threat Activity',
                data: Array.from({length: 30}, () => Math.floor(Math.random() * 200) + 50),
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#a0aec0' }
                }
            },
            scales: {
                x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } }
            }
        }
    });
}

function createGeographicChart() {
    const ctx = document.getElementById('geographicChart');
    if (!ctx) return;

    state.charts.geographic = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['United States', 'China', 'Russia', 'Germany', 'France', 'Others'],
            datasets: [{
                data: [28, 22, 18, 12, 8, 12],
                backgroundColor: [
                    '#ff3838',
                    '#ff6b35',
                    '#ffa726',
                    '#ffeb3b',
                    '#00d4ff',
                    '#3b82f6'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#a0aec0' }
                }
            }
        }
    });
}

function createAttackVectorChart() {
    const ctx = document.getElementById('attackVectorChart');
    if (!ctx) return;

    state.charts.attackVector = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Email', 'Web', 'Network', 'USB', 'Remote'],
            datasets: [{
                label: 'Attack Vectors',
                data: [42, 35, 28, 15, 22],
                backgroundColor: '#10b981'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } }
            }
        }
    });
}

// Dashboard updates
function updateDashboardMetrics() {
    const criticalCount = state.threats.filter(t => t.severity === 'critical').length;
    const totalThreats = state.threats.length;
    const ipCount = state.maliciousIPs.length;
    const phishingCount = state.phishingDomains.length;

    document.getElementById('metric-critical').textContent = criticalCount;
    document.getElementById('metric-threats').textContent = totalThreats;
    document.getElementById('metric-ips').textContent = ipCount;
    document.getElementById('metric-phishing').textContent = phishingCount;

    // Update global threat level
    let threatLevel = 'low';
    if (criticalCount > 10) threatLevel = 'critical';
    else if (criticalCount > 5) threatLevel = 'high';
    else if (criticalCount > 2) threatLevel = 'medium';

    const threatLevelElement = document.getElementById('globalThreatLevel');
    threatLevelElement.textContent = threatLevel.toUpperCase();
    threatLevelElement.className = `threat-level ${threatLevel}`;
}

function updateRecentThreats() {
    const container = document.getElementById('recentThreatsList');
    if (!container) return;

    const recentThreats = state.threats
        .filter(t => t.severity === 'critical' || t.severity === 'high')
        .slice(0, 5);

    container.innerHTML = recentThreats.map(threat => `
        <div class="threat-item">
            <div class="threat-item-info">
                <div class="threat-item-title">${threat.title}</div>
                <div class="threat-item-meta">
                    ${threat.type.toUpperCase()} • ${threat.source} • ${formatTime(threat.timestamp)}
                </div>
            </div>
            <span class="risk-badge ${threat.severity}">${threat.severity}</span>
        </div>
    `).join('');
}

// Threat Feed
function renderThreatFeed() {
    const container = document.getElementById('threatFeedList');
    if (!container) return;

    const filtered = filterThreats(state.threats);
    
    container.innerHTML = filtered.map((threat, index) => `
        <div class="threat-feed-item ${threat.severity}">
            <div class="threat-feed-header">
                <div>
                    <div class="threat-title">${threat.title}</div>
                    <div class="threat-meta">
                        <span>Type: ${threat.type.toUpperCase()}</span>
                        <span>Source: ${threat.source}</span>
                        <span>Time: ${formatTime(threat.timestamp)}</span>
                        ${threat.ipAddress ? `<span>IP: ${threat.ipAddress}</span>` : ''}
                    </div>
                </div>
                <span class="threat-severity ${threat.severity}">${threat.severity}</span>
            </div>
            <div class="threat-description">${threat.description}</div>
            <div class="threat-actions" style="margin-top: 1rem; display: flex; gap: 0.5rem;">
                <button class="btn-primary" onclick="showThreatSolution('${threat.id}')">Solution</button>
            </div>
        </div>
    `).join('');
}

function filterThreats(threats) {
    const searchTerm = document.getElementById('feedSearch')?.value.toLowerCase() || '';
    const severityFilter = document.getElementById('feedSeverityFilter')?.value || 'all';
    const typeFilter = document.getElementById('feedTypeFilter')?.value || 'all';

    return threats.filter(threat => {
        const matchesSearch = !searchTerm || 
            threat.title.toLowerCase().includes(searchTerm) ||
            threat.description.toLowerCase().includes(searchTerm) ||
            (threat.ipAddress && threat.ipAddress.includes(searchTerm));

        const matchesSeverity = severityFilter === 'all' || threat.severity === severityFilter;
        const matchesType = typeFilter === 'all' || threat.type === typeFilter;

        return matchesSearch && matchesSeverity && matchesType;
    });
}

// Malicious IPs
function renderMaliciousIPs() {
    const container = document.getElementById('maliciousIPTable');
    if (!container) return;

    const searchTerm = document.getElementById('ipSearch')?.value.toLowerCase() || '';
    const riskFilter = document.getElementById('ipRiskFilter')?.value || 'all';

    const filtered = state.maliciousIPs.filter(ip => {
        const matchesSearch = !searchTerm || ip.ip.includes(searchTerm);
        const matchesRisk = riskFilter === 'all' || ip.riskLevel === riskFilter;
        return matchesSearch && matchesRisk;
    });

    container.innerHTML = filtered.map(ip => `
        <tr>
            <td><code>${ip.ip}</code></td>
            <td>${ip.reputationScore}/100</td>
            <td><span class="risk-badge ${ip.riskLevel}">${ip.riskLevel}</span></td>
            <td>${ip.threatType}</td>
            <td>${formatDate(ip.firstSeen)}</td>
            <td>${formatDate(ip.lastSeen)}</td>
            <td>${ip.source}</td>
            <td>
                <button class="btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="showIPDetails('${ip.id}')">Details</button>
            </td>
        </tr>
    `).join('');
}

// Phishing Domains
function renderPhishingDomains() {
    const container = document.getElementById('phishingDomainTable');
    if (!container) return;

    const searchTerm = document.getElementById('domainSearch')?.value.toLowerCase() || '';
    const typeFilter = document.getElementById('domainTypeFilter')?.value || 'all';

    const filtered = state.phishingDomains.filter(domain => {
        const matchesSearch = !searchTerm || domain.domain.toLowerCase().includes(searchTerm);
        const matchesType = typeFilter === 'all' || domain.threatType === typeFilter;
        return matchesSearch && matchesType;
    });

    container.innerHTML = filtered.map(domain => `
        <tr>
            <td><code>${domain.domain}</code></td>
            <td>${domain.threatType}</td>
            <td>${domain.riskScore}/100</td>
            <td>${formatDate(domain.registrationDate)}</td>
            <td>${formatDate(domain.firstDetected)}</td>
            <td>
                <span class="risk-badge ${domain.status === 'Active' ? 'high' : 'low'}">
                    ${domain.status}
                </span>
            </td>
            <td>${domain.source}</td>
            <td>
                <button class="btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="showDomainDetails('${domain.id}')">Details</button>
            </td>
        </tr>
    `).join('');
}

// Malware Intelligence
function renderMalwareIntel() {
    const container = document.getElementById('malwareList');
    if (!container) return;

    const searchTerm = document.getElementById('malwareSearch')?.value.toLowerCase() || '';
    const typeFilter = document.getElementById('malwareTypeFilter')?.value || 'all';

    const filtered = state.malwareData.filter(malware => {
        const matchesSearch = !searchTerm ||
            malware.name.toLowerCase().includes(searchTerm) ||
            malware.hash.toLowerCase().includes(searchTerm) ||
            malware.type.toLowerCase().includes(searchTerm);
        const matchesType = typeFilter === 'all' || malware.type === typeFilter;
        return matchesSearch && matchesType;
    });

    container.innerHTML = filtered.map(malware => `
        <div class="malware-card">
            <div class="malware-header">
                <h4 class="malware-name">${malware.name}</h4>
                <span class="malware-type-badge">${malware.type}</span>
            </div>
            <div class="malware-hash">
                <strong>Hash:</strong> <code class="hash-value">${malware.hash}</code>
            </div>
            <div class="malware-details">
                <div class="detail-item">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value severity-badge ${malware.severity}">${malware.severity}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">First Seen:</span>
                    <span class="detail-value first-seen">${formatDate(malware.firstSeen)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Detections:</span>
                    <span class="detail-value detections">${malware.detections}</span>
                </div>
            </div>
            <div class="malware-description">${malware.description}</div>
            <div class="malware-actions">
                <button class="btn-secondary" onclick="showMalwareDetails('${malware.id}')">View Details</button>
                <button class="btn-secondary" onclick="exportMalwareIOC('${malware.id}')">Export IOC</button>
            </div>
        </div>
    `).join('');
}

// Analytics
function updateAnalyticsCharts() {
    // Charts are already created, just update if needed
    updateAnalyticsStats();
}

function updateAnalyticsStats() {
    const container = document.getElementById('analyticsStats');
    if (!container) return;

    const stats = [
        { label: 'Total Threats (30d)', value: state.threats.length * 12 },
        { label: 'Avg. Daily Threats', value: Math.round(state.threats.length * 12 / 30) },
        { label: 'Unique Malicious IPs', value: state.maliciousIPs.length },
        { label: 'Phishing Domains', value: state.phishingDomains.length },
        { label: 'Malware Samples', value: state.malwareData.length },
        { label: 'Active Alerts', value: state.alerts.filter(a => a.status !== 'resolved').length }
    ];

    container.innerHTML = stats.map(stat => `
        <div class="stat-item">
            <span class="stat-label">${stat.label}</span>
            <span class="stat-value">${stat.value.toLocaleString()}</span>
        </div>
    `).join('');
}

// Spam link checker
function handleSpamCheck() {
    const input = document.getElementById('spamLinkInput');
    const resultContainer = document.getElementById('spamResult');
    if (!input || !resultContainer) return;

    const url = input.value.trim();
    if (!url) {
        resultContainer.innerHTML = '<p class="muted">Enter a URL to analyze.</p>';
        return;
    }

    const result = evaluateLinkSpam(url);
    state.spamChecks.unshift(result);
    renderSpamResult(result);
}

function evaluateLinkSpam(url) {
    const lc = url.toLowerCase();
    const reasons = [];
    let score = 0;

    const spamKeywords = ['login', 'verify', 'update', 'secure', 'bank', 'gift', 'free', 'prize', 'bonus', 'win', 'reset'];
    const badTlds = ['.ru', '.cn', '.tk', '.top', '.xyz', '.gq', '.ml', '.cf'];
    const brandSpoof = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'bank', 'netflix'];

    spamKeywords.forEach(k => { if (lc.includes(k)) { score += 10; reasons.push(`Contains suspicious keyword: ${k}`); } });
    badTlds.forEach(t => { if (lc.endsWith(t) || lc.includes(t + '/')) { score += 20; reasons.push(`Uses high-risk TLD: ${t}`); } });
    brandSpoof.forEach(b => { if (lc.includes(b) && !lc.includes(`${b}.com`)) { score += 15; reasons.push(`Potential brand spoofing: ${b}`); } });
    if (lc.startsWith('http://')) { score += 10; reasons.push('Insecure protocol (HTTP)'); }
    if (lc.includes('@')) { score += 10; reasons.push('URL contains @ which can mask true destination'); }
    if ((lc.match(/\//g) || []).length > 4) { score += 5; reasons.push('Multiple path segments (obfuscation risk)'); }
    if (/[0-9a-f]{16,}/.test(lc)) { score += 8; reasons.push('Hex-like strings often used for tracking/obfuscation'); }

    const isSpam = score >= 30 || reasons.length >= 3;
    const riskLabel = score >= 60 ? 'critical' : score >= 40 ? 'high' : score >= 25 ? 'medium' : 'low';

    return {
        url,
        isSpam,
        score: Math.min(score, 100),
        reasons,
        riskLabel,
        checkedAt: new Date()
    };
}

function renderSpamResult(result) {
    const container = document.getElementById('spamResult');
    if (!container) return;

    if (!result) {
        container.innerHTML = '<p class="muted">Awaiting input...</p>';
        return;
    }

    if (!result.isSpam) {
        container.innerHTML = `
            <div class="spam-result-title">
                <span>Result: <strong>Likely Clean</strong></span>
                <span class="risk-badge low">low</span>
            </div>
            <p class="muted">No strong spam indicators detected.</p>
        `;
        return;
    }

    container.innerHTML = `
        <div class="spam-result-title">
            <span>Result: <strong>Potential Spam</strong></span>
            <span class="risk-badge ${result.riskLabel}">${result.riskLabel}</span>
        </div>
        <p>Score: ${result.score}/100</p>
        <h4 style="margin-top:0.5rem;">Reasons</h4>
        <ul class="spam-reasons">
            ${result.reasons.map(r => `<li>${r}</li>`).join('')}
        </ul>
        <p class="muted">Checked at ${formatTime(result.checkedAt)}</p>
    `;
}

// Alerts
function renderAlerts() {
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    const statusFilter = document.getElementById('alertStatusFilter')?.value || 'all';
    const severityFilter = document.getElementById('alertSeverityFilter')?.value || 'all';

    const filtered = state.alerts.filter(alert => {
        const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;
        const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
        return matchesStatus && matchesSeverity;
    });

    container.innerHTML = filtered.map(alert => `
        <div class="alert-card ${alert.severity}">
            <div class="alert-header">
                <div>
                    <div class="alert-title">${alert.title}</div>
                    <div class="alert-details">
                        <div class="alert-detail-item">
                            <span class="alert-detail-label">Source:</span>
                            <span class="alert-detail-value">${alert.source}</span>
                        </div>
                        <div class="alert-detail-item">
                            <span class="alert-detail-label">Indicator:</span>
                            <span class="alert-detail-value">${alert.indicator}</span>
                        </div>
                        <div class="alert-detail-item">
                            <span class="alert-detail-label">Affected Systems:</span>
                            <span class="alert-detail-value">${alert.affectedSystems}</span>
                        </div>
                        <div class="alert-detail-item">
                            <span class="alert-detail-label">Created:</span>
                            <span class="alert-detail-value">${formatTime(alert.createdAt)}</span>
                        </div>
                    </div>
                </div>
                <span class="alert-status ${alert.status}">${alert.status}</span>
            </div>
            <div class="alert-description" style="color: var(--text-secondary); margin-top: 1rem;">
                ${alert.description}
            </div>
            <div class="alert-actions">
                <button class="btn-primary" onclick="investigateAlert('${alert.id}')">Investigate</button>
                <button class="btn-secondary" onclick="dismissAlert('${alert.id}')">Dismiss</button>
                <button class="btn-secondary" onclick="exportAlert('${alert.id}')">Export</button>
            </div>
        </div>
    `).join('');
}

// Reports
function renderRecentReports() {
    const container = document.getElementById('reportsList');
    if (!container) return;

    const reports = [
        { id: 'r1', name: 'Daily Threat Summary', date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), type: 'PDF' },
        { id: 'r2', name: 'Weekly Incident Report', date: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000), type: 'PDF' },
        { id: 'r3', name: 'Threat Intelligence Export', date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), type: 'CSV' },
        { id: 'r4', name: 'Monthly Analytics', date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), type: 'PDF' }
    ];

    container.innerHTML = reports.map(report => `
        <div class="report-item">
            <div class="report-item-info">
                <h4>${report.name}</h4>
                <div class="report-item-meta">Generated ${formatDate(report.date)} • ${report.type}</div>
            </div>
            <button class="btn-secondary" onclick="downloadReport('${report.id}')">Download</button>
        </div>
    `).join('');
}

// Event Listeners
function setupEventListeners() {
    // Threat Feed
    document.getElementById('feedSearch')?.addEventListener('input', renderThreatFeed);
    document.getElementById('feedSeverityFilter')?.addEventListener('change', renderThreatFeed);
    document.getElementById('feedTypeFilter')?.addEventListener('change', renderThreatFeed);
    document.getElementById('refreshFeed')?.addEventListener('click', () => {
        state.threats.unshift(generateThreat());
        renderThreatFeed();
        updateDashboardMetrics();
    });

    // Malicious IPs
    document.getElementById('ipSearch')?.addEventListener('input', renderMaliciousIPs);
    document.getElementById('ipRiskFilter')?.addEventListener('change', renderMaliciousIPs);
    document.getElementById('refreshIPs')?.addEventListener('click', () => {
        state.maliciousIPs.unshift(generateMaliciousIP());
        renderMaliciousIPs();
    });

    // Phishing Domains
    document.getElementById('domainSearch')?.addEventListener('input', renderPhishingDomains);
    document.getElementById('domainTypeFilter')?.addEventListener('change', renderPhishingDomains);
    document.getElementById('refreshDomains')?.addEventListener('click', () => {
        state.phishingDomains.unshift(generatePhishingDomain());
        renderPhishingDomains();
    });

    // Spam checker
    document.getElementById('spamCheckBtn')?.addEventListener('click', handleSpamCheck);
    document.getElementById('spamLinkInput')?.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') handleSpamCheck();
    });

    // Malware
    document.getElementById('malwareSearch')?.addEventListener('input', renderMalwareIntel);
    document.getElementById('malwareTypeFilter')?.addEventListener('change', renderMalwareIntel);
    document.getElementById('refreshMalware')?.addEventListener('click', () => {
        state.malwareData.unshift(generateMalwareSample());
        renderMalwareIntel();
    });

    // Alerts
    document.getElementById('alertStatusFilter')?.addEventListener('change', renderAlerts);
    document.getElementById('alertSeverityFilter')?.addEventListener('change', renderAlerts);
    document.getElementById('refreshAlerts')?.addEventListener('click', () => {
        state.alerts.unshift(generateAlert());
        renderAlerts();
        updateDashboardMetrics();
    });

    // Reports
    document.getElementById('reportForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        generateReport();
    });

    // Analytics
    document.getElementById('analyticsTimeRange')?.addEventListener('change', (e) => {
        updateAnalyticsChartsWithTimeRange(e.target.value);
    });

    // Chatbot
    document.getElementById('chatbotToggle')?.addEventListener('click', toggleChatbot);
    document.getElementById('chatbotClose')?.addEventListener('click', toggleChatbot);
    document.getElementById('chatSend')?.addEventListener('click', sendChatMessage);
    document.getElementById('chatInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChatMessage();
        }
    });

    // AI Suggestions
    document.getElementById('suggestionsToggle')?.addEventListener('click', toggleSuggestions);
    document.getElementById('suggestionsClose')?.addEventListener('click', toggleSuggestions);
    document.getElementById('generateSuggestion')?.addEventListener('click', generateSuggestion);

    // Modal close handlers
    document.getElementById('modalClose')?.addEventListener('click', closeModal);
    document.getElementById('modalOverlay')?.addEventListener('click', (e) => {
        if (e.target.id === 'modalOverlay') {
            closeModal();
        }
    });

    // Close modal on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
}

function generateReport() {
    const type = document.getElementById('reportType').value;
    const timeRange = document.getElementById('reportTimeRange').value;
    const format = document.getElementById('reportFormat').value;
    const includeCharts = document.getElementById('includeCharts').checked;

    // Simulate report generation
    const reportData = {
        type: type,
        timeRange: timeRange,
        format: format,
        includeCharts: includeCharts,
        generatedAt: new Date().toISOString(),
        threatsCount: state.threats.length,
        alertsCount: state.alerts.length,
        maliciousIPsCount: state.maliciousIPs.length,
        phishingDomainsCount: state.phishingDomains.length,
        malwareSamplesCount: state.malwareData.length
    };

    let reportContent = '';
    if (format === 'json') {
        reportContent = JSON.stringify(reportData, null, 2);
    } else if (format === 'csv') {
        reportContent = `Report Type,Time Range,Threats,Alerts,Malicious IPs,Phishing Domains,Malware Samples\n`;
        reportContent += `${type},${timeRange},${reportData.threatsCount},${reportData.alertsCount},${reportData.maliciousIPsCount},${reportData.phishingDomainsCount},${reportData.malwareSamplesCount}`;
    } else {
        reportContent = `Cyber Threat Intelligence Report\n`;
        reportContent += `Generated: ${new Date(reportData.generatedAt).toLocaleString()}\n`;
        reportContent += `Type: ${type}\n`;
        reportContent += `Time Range: ${timeRange}\n\n`;
        reportContent += `Summary Statistics:\n`;
        reportContent += `- Total Threats: ${reportData.threatsCount}\n`;
        reportContent += `- Active Alerts: ${reportData.alertsCount}\n`;
        reportContent += `- Malicious IPs: ${reportData.maliciousIPsCount}\n`;
        reportContent += `- Phishing Domains: ${reportData.phishingDomainsCount}\n`;
        reportContent += `- Malware Samples: ${reportData.malwareSamplesCount}\n`;
    }

    const blob = new Blob([reportContent], { type: format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_report_${Date.now()}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert(`Report generated successfully!\n\nType: ${type}\nTime Range: ${timeRange}\nFormat: ${format}\nInclude Charts: ${includeCharts}\n\nFile downloaded: ${a.download}`);
    
    // Refresh reports list
    setTimeout(() => {
        renderRecentReports();
    }, 500);
}

// Real-time updates
function startRealTimeUpdates() {
    state.updateInterval = setInterval(() => {
        // Add new threats occasionally
        if (Math.random() > 0.7) {
            state.threats.unshift(generateThreat());
            if (state.currentModule === 'threat-feed') {
                renderThreatFeed();
            }
        }

        // Add new alerts occasionally
        if (Math.random() > 0.8) {
            state.alerts.unshift(generateAlert());
            if (state.currentModule === 'alerts') {
                renderAlerts();
            }
        }

        // Update dashboard if active
        if (state.currentModule === 'dashboard') {
            updateDashboardMetrics();
            updateRecentThreats();
        }

        // Update charts periodically
        if (state.currentModule === 'dashboard' || state.currentModule === 'analytics') {
            updateChartsData();
        }
    }, 10000); // Update every 10 seconds
}

function updateChartsData() {
    // Update threat trends chart
    if (state.charts.threatTrends) {
        const newCritical = Math.floor(Math.random() * 20) + 5;
        const newHigh = Math.floor(Math.random() * 30) + 10;
        const newMedium = Math.floor(Math.random() * 40) + 15;
        const newLow = Math.floor(Math.random() * 50) + 20;

        state.charts.threatTrends.data.datasets[0].data.shift();
        state.charts.threatTrends.data.datasets[0].data.push(newCritical);
        state.charts.threatTrends.data.datasets[1].data.shift();
        state.charts.threatTrends.data.datasets[1].data.push(newHigh);
        state.charts.threatTrends.data.datasets[2].data.shift();
        state.charts.threatTrends.data.datasets[2].data.push(newMedium);
        state.charts.threatTrends.data.datasets[3].data.shift();
        state.charts.threatTrends.data.datasets[3].data.push(newLow);
        state.charts.threatTrends.update('none');
    }
}

// Utility functions
function formatTime(date) {
    if (!(date instanceof Date)) date = new Date(date);
    const now = new Date();
    const diff = now - date;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
}

function formatDate(date) {
    if (!(date instanceof Date)) date = new Date(date);
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
    });
}

// Chatbot (Gemini) and AI Suggestions
function toggleChatbot() {
    const widget = document.getElementById('chatWidget');
    widget?.classList.toggle('active');
}

function appendChatBubble(role, text) {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const bubble = document.createElement('div');
    bubble.className = `chat-message ${role}`;
    bubble.innerHTML = `<div class="chat-bubble">${text}</div>`;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    const message = input.value.trim();
    if (!message) return;

    appendChatBubble('user', message);
    input.value = '';

    const apiKey = document.getElementById('geminiApiKey')?.value.trim();
    const thinking = 'Analyzing with Gemini...';
    appendChatBubble('assistant', thinking);

    const reply = await chatWithGemini(message, apiKey);
    const container = document.getElementById('chatMessages');
    // remove last assistant placeholder
    if (container && container.lastChild && container.lastChild.textContent === thinking) {
        container.removeChild(container.lastChild);
    }
    appendChatBubble('assistant', reply);
}

async function chatWithGemini(prompt, apiKey) {
    // If no API key, return simulated guidance
    if (!apiKey) {
        return generateLocalGuidance(prompt);
    }

    try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{
                    parts: [{ text: `You are a cyber security assistant. Be concise and actionable.\n\nQuestion: ${prompt}` }]
                }],
                safetySettings: [
                    { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_LOW_AND_ABOVE" },
                    { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_LOW_AND_ABOVE" }
                ]
            })
        });

        if (!response.ok) throw new Error('Gemini API request failed');
        const data = await response.json();
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) throw new Error('No response text');
        return text;
    } catch (err) {
        console.error(err);
        return generateLocalGuidance(prompt, true);
    }
}

function generateLocalGuidance(prompt, isFallback = false) {
    const templates = [
        'Check logs on impacted hosts: auth, process, network. Contain host if malicious activity is confirmed.',
        'Harden controls: enable MFA, enforce least privilege, patch vulnerable software, and block the indicator at firewall/EDR.',
        'Hunt for IOCs across SIEM: hash, domain, IP, user, process lineage, and outbound connections.',
        'If ransomware: isolate, snapshot evidence, restore from clean backups, and rotate credentials.',
        'For phishing: purge malicious emails, reset compromised accounts, enable DMARC/DKIM/SPF, educate users.',
        'For malware: quarantine binaries, upload hash to threat intel, and block execution via EDR rules.'
    ];
    const hint = templates[Math.floor(Math.random() * templates.length)];
    return `${isFallback ? '[Fallback] ' : ''}${hint}\n\nPrompt understood: "${prompt.slice(0, 200)}"`;
}

function toggleSuggestions() {
    const panel = document.getElementById('suggestionsPanel');
    if (!panel) return;
    const willOpen = !panel.classList.contains('active');
    panel.classList.toggle('active');
    if (willOpen && state.suggestions.length === 0) {
        generateSuggestion();
    }
}

function generateSuggestion() {
    const ctx = document.getElementById('suggestionContext')?.value.trim() || 'general security issue';
    const suggestions = [
        `Run IOC sweep for "${ctx}" across SIEM, EDR, DNS, proxy logs; auto-block new hits.`,
        `Prioritize containment: isolate affected hosts related to "${ctx}", revoke active sessions, and rotate keys.`,
        `Patch and harden: apply latest fixes, disable unused services, enforce MFA/least privilege for "${ctx}".`,
        `Create detection: add Sigma/EDR rule for process + network pattern tied to "${ctx}".`,
        `Recovery playbook: validate backups, rehearse restore, and add post-incident review for "${ctx}".`
    ];
    const pick = suggestions[Math.floor(Math.random() * suggestions.length)];
    state.suggestions.unshift({ text: pick, createdAt: new Date() });
    renderSuggestions();
}

function renderSuggestions() {
    const container = document.getElementById('suggestionsList');
    if (!container) return;
    if (!state.suggestions.length) {
        container.innerHTML = '<p class="muted">No suggestions yet.</p>';
        return;
    }
    container.innerHTML = state.suggestions.slice(0, 5).map(s => `
        <div class="suggestion-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <strong>Suggestion</strong>
                <span class="muted" style="font-size:0.8rem;">${formatTime(s.createdAt)}</span>
            </div>
            <p style="margin-top:0.35rem;">${s.text}</p>
        </div>
    `).join('');
}

// Modal functions
function showModal(title, content, footer = '') {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = content;
    document.getElementById('modalFooter').innerHTML = footer;
    document.getElementById('modalOverlay').classList.add('active');
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('active');
}

// Threat Solution
function showThreatSolution(threatId) {
    const threat = state.threats.find(t => t.id === threatId);
    if (!threat) return;

    const solutions = {
        'malware': `
            <h4>Solution for Malware Threat</h4>
            <p><strong>Immediate Actions:</strong></p>
            <ul>
                <li>Isolate affected systems from the network immediately</li>
                <li>Run full antivirus scan on all systems</li>
                <li>Check for unauthorized processes and services</li>
                <li>Review firewall logs for suspicious outbound connections</li>
                <li>Update antivirus definitions and scan again</li>
            </ul>
            <p><strong>Prevention Measures:</strong></p>
            <ul>
                <li>Implement application whitelisting</li>
                <li>Enable Windows Defender or equivalent endpoint protection</li>
                <li>Keep all systems updated with latest security patches</li>
                <li>Educate users about safe browsing practices</li>
                <li>Implement network segmentation</li>
            </ul>
            <p><strong>Monitoring:</strong></p>
            <ul>
                <li>Monitor network traffic for anomalies</li>
                <li>Set up automated threat detection alerts</li>
                <li>Regular security assessments</li>
            </ul>
        `,
        'phishing': `
            <h4>Solution for Phishing Threat</h4>
            <p><strong>Immediate Actions:</strong></p>
            <ul>
                <li>Block the malicious domain/IP address at firewall level</li>
                <li>Scan email systems for phishing emails</li>
                <li>Check if any credentials were compromised</li>
                <li>Review email filtering rules and update as needed</li>
                <li>Notify affected users to change passwords if compromised</li>
            </ul>
            <p><strong>Prevention Measures:</strong></p>
            <ul>
                <li>Implement email authentication (SPF, DKIM, DMARC)</li>
                <li>Deploy advanced email security solutions</li>
                <li>Conduct regular phishing awareness training</li>
                <li>Enable multi-factor authentication (MFA)</li>
                <li>Use URL filtering and reputation services</li>
            </ul>
            <p><strong>Monitoring:</strong></p>
            <ul>
                <li>Monitor email traffic patterns</li>
                <li>Track credential login attempts</li>
                <li>Set up alerts for suspicious email activity</li>
            </ul>
        `,
        'malicious-ip': `
            <h4>Solution for Malicious IP Threat</h4>
            <p><strong>Immediate Actions:</strong></p>
            <ul>
                <li>Block the IP address in firewall and IDS/IPS systems</li>
                <li>Review logs for any connections from this IP</li>
                <li>Check for any data exfiltration attempts</li>
                <li>Scan systems that may have connected to this IP</li>
                <li>Add IP to threat intelligence feeds</li>
            </ul>
            <p><strong>Prevention Measures:</strong></p>
            <ul>
                <li>Implement IP reputation filtering</li>
                <li>Use geolocation-based blocking for known threat regions</li>
                <li>Deploy network monitoring and IDS/IPS solutions</li>
                <li>Keep threat intelligence feeds updated</li>
                <li>Implement network segmentation</li>
            </ul>
            <p><strong>Monitoring:</strong></p>
            <ul>
                <li>Monitor network connections and traffic patterns</li>
                <li>Set up automated alerts for known malicious IPs</li>
                <li>Regular review of firewall and IDS logs</li>
            </ul>
        `,
        'ddos': `
            <h4>Solution for DDoS Attack</h4>
            <p><strong>Immediate Actions:</strong></p>
            <ul>
                <li>Activate DDoS mitigation services or appliances</li>
                <li>Identify and block source IPs at network edge</li>
                <li>Scale up resources if using cloud infrastructure</li>
                <li>Enable rate limiting on affected services</li>
                <li>Notify ISP and DDoS mitigation provider</li>
            </ul>
            <p><strong>Prevention Measures:</strong></p>
            <ul>
                <li>Deploy DDoS protection services (cloud-based or on-premise)</li>
                <li>Implement rate limiting and traffic shaping</li>
                <li>Use Content Delivery Network (CDN) for web services</li>
                <li>Configure firewall rules to drop suspicious traffic</li>
                <li>Implement network redundancy and load balancing</li>
            </ul>
            <p><strong>Monitoring:</strong></p>
            <ul>
                <li>Monitor network traffic volumes continuously</li>
                <li>Set up automated alerts for unusual traffic spikes</li>
                <li>Regular network capacity planning</li>
            </ul>
        `,
        'exploit': `
            <h4>Solution for Exploit Attempt</h4>
            <p><strong>Immediate Actions:</strong></p>
            <ul>
                <li>Block the source IP address immediately</li>
                <li>Check if the exploit was successful</li>
                <li>Apply the relevant security patch if available</li>
                <li>Review application logs for signs of compromise</li>
                <li>Scan systems for indicators of compromise (IOCs)</li>
            </ul>
            <p><strong>Prevention Measures:</strong></p>
            <ul>
                <li>Keep all software and systems updated with latest patches</li>
                <li>Implement Web Application Firewall (WAF)</li>
                <li>Use intrusion detection/prevention systems</li>
                <li>Conduct regular vulnerability assessments</li>
                <li>Implement principle of least privilege</li>
            </ul>
            <p><strong>Monitoring:</strong></p>
            <ul>
                <li>Monitor for exploit attempts and patterns</li>
                <li>Track CVE databases for new vulnerabilities</li>
                <li>Set up alerts for known exploit signatures</li>
            </ul>
        `
    };

    const solution = solutions[threat.type] || solutions['malware'];
    const content = `
        <div class="detail-row">
            <span class="detail-row-label">Threat:</span>
            <span class="detail-row-value">${threat.title}</span>
        </div>
        <div class="detail-row">
            <span class="detail-row-label">Type:</span>
            <span class="detail-row-value">${threat.type.toUpperCase()}</span>
        </div>
        <div class="detail-row">
            <span class="detail-row-label">Severity:</span>
            <span class="detail-row-value"><span class="risk-badge ${threat.severity}">${threat.severity}</span></span>
        </div>
        ${solution}
    `;

    showModal('Threat Solution', content, '<button class="btn-primary" onclick="closeModal()">Close</button>');
}

// IP Details
function showIPDetails(ipId) {
    const ip = state.maliciousIPs.find(i => i.id === ipId);
    if (!ip) return;

    const content = `
        <div class="detail-grid">
            <div class="detail-row">
                <span class="detail-row-label">IP Address:</span>
                <span class="detail-row-value"><code>${ip.ip}</code></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Reputation Score:</span>
                <span class="detail-row-value">${ip.reputationScore}/100</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Risk Level:</span>
                <span class="detail-row-value"><span class="risk-badge ${ip.riskLevel}">${ip.riskLevel}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Threat Type:</span>
                <span class="detail-row-value">${ip.threatType}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">First Seen:</span>
                <span class="detail-row-value">${formatDate(ip.firstSeen)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Last Seen:</span>
                <span class="detail-row-value">${formatDate(ip.lastSeen)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Intelligence Source:</span>
                <span class="detail-row-value">${ip.source}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Timespan Active:</span>
                <span class="detail-row-value">${Math.round((ip.lastSeen - ip.firstSeen) / (1000 * 60 * 60 * 24))} days</span>
            </div>
        </div>
        <h4>Threat Analysis</h4>
        <p>This IP address has been identified as ${ip.threatType.toLowerCase()} with a reputation score of ${ip.reputationScore}/100. 
        It has been active for approximately ${Math.round((ip.lastSeen - ip.firstSeen) / (1000 * 60 * 60 * 24))} days, 
        indicating ${ip.reputationScore > 80 ? 'a persistent and high-risk threat' : 'ongoing malicious activity'}.</p>
        <h4>Recommended Actions</h4>
        <ul>
            <li>Block this IP address in firewall rules</li>
            <li>Add to threat intelligence blocklists</li>
            <li>Review network logs for any connections from this IP</li>
            <li>Monitor for similar patterns from related IP ranges</li>
            <li>Update IDS/IPS signatures if applicable</li>
        </ul>
    `;

    showModal('Malicious IP Details', content, '<button class="btn-primary" onclick="closeModal()">Close</button>');
}

// Domain Details
function showDomainDetails(domainId) {
    const domain = state.phishingDomains.find(d => d.id === domainId);
    if (!domain) return;

    const content = `
        <div class="detail-grid">
            <div class="detail-row">
                <span class="detail-row-label">Domain:</span>
                <span class="detail-row-value"><code>${domain.domain}</code></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Threat Type:</span>
                <span class="detail-row-value">${domain.threatType}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Risk Score:</span>
                <span class="detail-row-value">${domain.riskScore}/100</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Registration Date:</span>
                <span class="detail-row-value">${formatDate(domain.registrationDate)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">First Detected:</span>
                <span class="detail-row-value">${formatDate(domain.firstDetected)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Status:</span>
                <span class="detail-row-value"><span class="risk-badge ${domain.status === 'Active' ? 'high' : 'low'}">${domain.status}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Intelligence Source:</span>
                <span class="detail-row-value">${domain.source}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Domain Age:</span>
                <span class="detail-row-value">${Math.round((Date.now() - domain.registrationDate) / (1000 * 60 * 60 * 24))} days</span>
            </div>
        </div>
        <h4>Threat Analysis</h4>
        <p>This domain has been identified as a ${domain.threatType} threat with a risk score of ${domain.riskScore}/100. 
        The domain is currently <strong>${domain.status.toLowerCase()}</strong> and was first detected 
        ${Math.round((Date.now() - domain.firstDetected) / (1000 * 60 * 60 * 24))} days ago.</p>
        <h4>Recommended Actions</h4>
        <ul>
            <li>Block this domain in web filters and DNS filters</li>
            <li>Add to email security blocklists</li>
            <li>Update proxy/URL filtering rules</li>
            <li>Monitor for similar domain registrations (typosquatting)</li>
            <li>Alert users if domain was used in phishing campaigns</li>
            ${domain.status === 'Active' ? '<li><strong>URGENT:</strong> Domain is currently active - immediate blocking recommended</li>' : ''}
        </ul>
    `;

    showModal('Phishing Domain Details', content, '<button class="btn-primary" onclick="closeModal()">Close</button>');
}

// Malware Details
function showMalwareDetails(malwareId) {
    const malware = state.malwareData.find(m => m.id === malwareId);
    if (!malware) return;

    const content = `
        <div class="detail-grid">
            <div class="detail-row">
                <span class="detail-row-label">Malware Name:</span>
                <span class="detail-row-value">${malware.name}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Type:</span>
                <span class="detail-row-value">${malware.type}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Severity:</span>
                <span class="detail-row-value"><span class="severity-badge ${malware.severity}">${malware.severity}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">SHA-256 Hash:</span>
                <span class="detail-row-value"><code>${malware.hash}</code></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">First Seen:</span>
                <span class="detail-row-value">${formatDate(malware.firstSeen)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Detections:</span>
                <span class="detail-row-value">${malware.detections}</span>
            </div>
        </div>
        <h4>Description</h4>
        <p>${malware.description}</p>
        <h4>IOC (Indicators of Compromise)</h4>
        <ul>
            <li><strong>File Hash (SHA-256):</strong> <code>${malware.hash}</code></li>
            <li><strong>Threat Type:</strong> ${malware.type}</li>
            <li><strong>Detection Rate:</strong> ${malware.detections} security vendors have detected this threat</li>
        </ul>
        <h4>Recommended Actions</h4>
        <ul>
            <li>Quarantine any files matching this hash immediately</li>
            <li>Update antivirus definitions and scan all systems</li>
            <li>Block file hash in endpoint protection systems</li>
            <li>Review system logs for execution of files with this hash</li>
            <li>If detected, isolate affected systems and conduct forensic analysis</li>
        </ul>
    `;

    showModal('Malware Details', content, '<button class="btn-primary" onclick="closeModal()">Close</button>');
}

// Export Malware IOC
function exportMalwareIOC(malwareId) {
    const malware = state.malwareData.find(m => m.id === malwareId);
    if (!malware) return;

    const iocData = {
        type: 'malware',
        name: malware.name,
        hash_sha256: malware.hash,
        type_category: malware.type,
        severity: malware.severity,
        first_seen: malware.firstSeen.toISOString(),
        detections: malware.detections,
        description: malware.description,
        export_date: new Date().toISOString()
    };

    const iocJson = JSON.stringify(iocData, null, 2);
    const blob = new Blob([iocJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malware_ioc_${malware.name.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert(`Malware IOC exported successfully!\n\nFile: ${a.download}\n\nIncludes:\n- SHA-256 Hash\n- Threat Type\n- Severity\n- First Seen Date\n- Detection Count`);
}

// Alert Actions
function investigateAlert(alertId) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (!alert) return;

    alert.status = 'investigating';
    renderAlerts();
    
    const content = `
        <h4>Alert Investigation Started</h4>
        <p>The alert "${alert.title}" has been marked as <strong>investigating</strong>.</p>
        <div class="detail-grid">
            <div class="detail-row">
                <span class="detail-row-label">Alert ID:</span>
                <span class="detail-row-value">${alert.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Severity:</span>
                <span class="detail-row-value"><span class="risk-badge ${alert.severity}">${alert.severity}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Indicator:</span>
                <span class="detail-row-value">${alert.indicator}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Affected Systems:</span>
                <span class="detail-row-value">${alert.affectedSystems}</span>
            </div>
        </div>
        <h4>Investigation Steps</h4>
        <ul>
            <li>Review logs for the indicator: ${alert.indicator}</li>
            <li>Check ${alert.affectedSystems} affected system(s) for compromise</li>
            <li>Analyze network traffic patterns</li>
            <li>Collect and preserve evidence</li>
            <li>Document findings in incident management system</li>
        </ul>
    `;

    showModal('Alert Investigation', content, '<button class="btn-primary" onclick="closeModal()">Close</button>');
}

function dismissAlert(alertId) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (!alert) return;

    if (confirm(`Are you sure you want to dismiss the alert "${alert.title}"?`)) {
        alert.status = 'resolved';
        renderAlerts();
        alert('Alert dismissed and marked as resolved.');
    }
}

function exportAlert(alertId) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (!alert) return;

    const alertData = {
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        status: alert.status,
        description: alert.description,
        source: alert.source,
        indicator: alert.indicator,
        affected_systems: alert.affectedSystems,
        created_at: alert.createdAt.toISOString(),
        export_date: new Date().toISOString()
    };

    const alertJson = JSON.stringify(alertData, null, 2);
    const blob = new Blob([alertJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alert_${alert.id}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert(`Alert exported successfully!\n\nFile: ${a.download}`);
}

// Report Actions
function downloadReport(reportId) {
    const reports = [
        { id: 'r1', name: 'Daily Threat Summary', date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), type: 'PDF' },
        { id: 'r2', name: 'Weekly Incident Report', date: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000), type: 'PDF' },
        { id: 'r3', name: 'Threat Intelligence Export', date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), type: 'CSV' },
        { id: 'r4', name: 'Monthly Analytics', date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), type: 'PDF' }
    ];

    const report = reports.find(r => r.id === reportId);
    if (!report) return;

    alert(`Downloading ${report.name}...\n\nFormat: ${report.type}\nGenerated: ${formatDate(report.date)}\n\nIn a production environment, this would download the actual report file.`);
}

// Analytics Time Range Update
function updateAnalyticsChartsWithTimeRange(timeRange) {
    if (!state.charts.analyticsTimeline) return;

    let days, dataPoints, labels;

    switch(timeRange) {
        case '24h':
            days = 24;
            dataPoints = Array.from({length: 24}, (_, i) => {
                const date = new Date();
                date.setHours(date.getHours() - (23 - i));
                return { date, value: Math.floor(Math.random() * 100) + 20 };
            });
            labels = dataPoints.map((d, i) => {
                const h = d.date.getHours();
                return h.toString().padStart(2, '0') + ':00';
            });
            break;
        case '7d':
            days = 7;
            dataPoints = Array.from({length: 7}, (_, i) => {
                const date = new Date();
                date.setDate(date.getDate() - (6 - i));
                return { date, value: Math.floor(Math.random() * 500) + 100 };
            });
            labels = dataPoints.map(d => {
                const day = d.date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                return day;
            });
            break;
        case '30d':
            days = 30;
            dataPoints = Array.from({length: 30}, (_, i) => {
                const date = new Date();
                date.setDate(date.getDate() - (29 - i));
                return { date, value: Math.floor(Math.random() * 200) + 50 };
            });
            labels = dataPoints.map(d => {
                const day = d.date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                return day;
            });
            break;
        case '90d':
            days = 90;
            dataPoints = Array.from({length: 12}, (_, i) => {
                const date = new Date();
                date.setDate(date.getDate() - (89 - (i * 7)));
                return { date, value: Math.floor(Math.random() * 1000) + 200 };
            });
            labels = dataPoints.map(d => {
                const day = d.date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                return day;
            });
            break;
        default:
            return;
    }

    state.charts.analyticsTimeline.data.labels = labels;
    state.charts.analyticsTimeline.data.datasets[0].data = dataPoints.map(d => d.value);
    state.charts.analyticsTimeline.update();
}

// Initial render
setTimeout(() => {
    updateDashboardMetrics();
    updateRecentThreats();
    renderThreatFeed();
    renderMaliciousIPs();
    renderPhishingDomains();
    renderMalwareIntel();
    renderAlerts();
    renderRecentReports();
    updateAnalyticsStats();
    renderSpamResult();
    renderSuggestions();
}, 100);
