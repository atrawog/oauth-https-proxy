// API Client
class CertificateAPI {
    constructor() {
        this.baseURL = '';
        this.token = localStorage.getItem('bearer_token');
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('bearer_token', token);
    }

    clearToken() {
        this.token = null;
        localStorage.removeItem('bearer_token');
    }

    async request(method, endpoint, data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            }
        };

        if (this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(`${this.baseURL}${endpoint}`, options);
        
        if (response.status === 401) {
            this.clearToken();
            showLogin();
            throw new Error('Authentication failed');
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Request failed');
        }

        return response.json();
    }

    async getCertificates() {
        return this.request('GET', '/certificates');
    }

    async getCertificate(certName) {
        return this.request('GET', `/certificates/${certName}`);
    }

    async getCertificateStatus(certName) {
        return this.request('GET', `/certificates/${certName}/status`);
    }

    async createCertificate(data) {
        return this.request('POST', '/certificates', data);
    }

    async renewCertificate(certName) {
        return this.request('POST', `/certificates/${certName}/renew`);
    }

    async convertCertificateToProduction(certName) {
        return this.request('POST', `/certificates/${certName}/convert-to-production`);
    }

    async deleteDomain(certName, domain) {
        return this.request('DELETE', `/certificates/${certName}/domains/${domain}`);
    }
    
    // Proxy target methods
    async getProxyTargets() {
        return this.request('GET', '/proxy/targets');
    }
    
    async createProxyTarget(data) {
        return this.request('POST', '/proxy/targets', data);
    }
    
    async updateProxyTarget(hostname, data) {
        return this.request('PUT', `/proxy/targets/${hostname}`, data);
    }
    
    async deleteProxyTarget(hostname, deleteCert = false) {
        return this.request('DELETE', `/proxy/targets/${hostname}?delete_certificate=${deleteCert}`);
    }
    
    // Route methods
    async getRoutes() {
        return this.request('GET', '/routes');
    }
    
    async createRoute(data) {
        return this.request('POST', '/routes', data);
    }
    
    async updateRoute(routeId, data) {
        return this.request('PUT', `/routes/${routeId}`, data);
    }
    
    async deleteRoute(routeId) {
        return this.request('DELETE', `/routes/${routeId}`);
    }
    
    // Proxy route methods
    async getProxyRoutes(hostname) {
        return this.request('GET', `/proxy/targets/${hostname}/routes`);
    }
    
    async updateProxyRoutes(hostname, data) {
        return this.request('PUT', `/proxy/targets/${hostname}/routes`, data);
    }
    
    async enableProxyRoute(hostname, routeId) {
        return this.request('POST', `/proxy/targets/${hostname}/routes/${routeId}/enable`);
    }
    
    async disableProxyRoute(hostname, routeId) {
        return this.request('POST', `/proxy/targets/${hostname}/routes/${routeId}/disable`);
    }
}

// Initialize API client
const api = new CertificateAPI();

// UI State Management
let currentTab = 'certificates';
let certificates = [];
let proxyTargets = [];
let routes = [];
let statusPollingIntervals = new Map();

// DOM Elements
const loginSection = document.getElementById('login-section');
const dashboardSection = document.getElementById('dashboard-section');
const loginForm = document.getElementById('login-form');
const newCertForm = document.getElementById('new-certificate-form');
const newProxyForm = document.getElementById('new-proxy-form');
const logoutBtn = document.getElementById('logout-btn');
const authStatus = document.getElementById('auth-status');
const certModal = document.getElementById('cert-modal');
const certDetails = document.getElementById('cert-details');
const closeModal = document.querySelector('.close');

// Tab buttons
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');

// Event Listeners
loginForm.addEventListener('submit', handleLogin);
newCertForm.addEventListener('submit', handleNewCertificate);
newProxyForm.addEventListener('submit', handleNewProxyTarget);

// Add button listeners
document.getElementById('add-certificate-btn')?.addEventListener('click', toggleCertificateForm);
document.getElementById('add-proxy-btn')?.addEventListener('click', toggleProxyForm);
document.getElementById('add-route-btn')?.addEventListener('click', toggleRouteForm);

// Settings form listener
const emailSettingsForm = document.getElementById('email-settings-form');
if (emailSettingsForm) {
    emailSettingsForm.addEventListener('submit', handleEmailUpdate);
}
logoutBtn.addEventListener('click', handleLogout);
closeModal.addEventListener('click', () => certModal.classList.add('hidden'));

tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        const tab = button.getAttribute('data-tab');
        switchTab(tab);
    });
});

// Authentication
async function handleLogin(e) {
    e.preventDefault();
    const token = document.getElementById('token').value;
    
    try {
        api.setToken(token);
        await api.getCertificates(); // Test the token
        showDashboard();
        showNotification('Successfully authenticated', 'success');
    } catch (error) {
        api.clearToken();
        showNotification('Invalid token', 'error');
    }
}

function handleLogout() {
    api.clearToken();
    showLogin();
    showNotification('Logged out', 'info');
}

function showLogin() {
    loginSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    logoutBtn.classList.add('hidden');
    authStatus.textContent = '';
    document.getElementById('token').value = '';
    
    // Clear any polling intervals
    statusPollingIntervals.forEach(interval => clearInterval(interval));
    statusPollingIntervals.clear();
}

function showDashboard() {
    loginSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    logoutBtn.classList.remove('hidden');
    authStatus.textContent = 'Authenticated';
    loadCertificates();
}

// Tab Management
function switchTab(tab) {
    currentTab = tab;
    
    tabButtons.forEach(button => {
        if (button.getAttribute('data-tab') === tab) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });

    tabContents.forEach(content => {
        if (content.id === `${tab}-tab`) {
            content.classList.remove('hidden');
            content.classList.add('active');
        } else {
            content.classList.add('hidden');
            content.classList.remove('active');
        }
    });

    // Hide forms when switching tabs
    hideCertificateForm();
    hideProxyForm();
    hideRouteForm();

    if (tab === 'certificates') {
        loadCertificates();
    } else if (tab === 'proxies') {
        loadProxyTargets();
    } else if (tab === 'routes') {
        loadRoutes();
    } else if (tab === 'settings') {
        loadTokenInfo();
    }
}

// Form Toggle Functions
function toggleCertificateForm() {
    const formContainer = document.getElementById('new-certificate-form-container');
    const addButton = document.getElementById('add-certificate-btn');
    
    if (formContainer.classList.contains('hidden')) {
        formContainer.classList.remove('hidden');
        addButton.textContent = 'Cancel';
        addButton.classList.add('btn-secondary');
        addButton.classList.remove('btn-primary');
    } else {
        formContainer.classList.add('hidden');
        addButton.textContent = 'Add Certificate';
        addButton.classList.remove('btn-secondary');
        addButton.classList.add('btn-primary');
    }
}

function hideCertificateForm() {
    const formContainer = document.getElementById('new-certificate-form-container');
    const addButton = document.getElementById('add-certificate-btn');
    
    if (formContainer && addButton) {
        formContainer.classList.add('hidden');
        addButton.textContent = 'Add Certificate';
        addButton.classList.remove('btn-secondary');
        addButton.classList.add('btn-primary');
    }
}

function toggleProxyForm() {
    const formContainer = document.getElementById('new-proxy-form-container');
    const addButton = document.getElementById('add-proxy-btn');
    
    if (formContainer.classList.contains('hidden')) {
        formContainer.classList.remove('hidden');
        addButton.textContent = 'Cancel';
        addButton.classList.add('btn-secondary');
        addButton.classList.remove('btn-primary');
    } else {
        formContainer.classList.add('hidden');
        addButton.textContent = 'Add Proxy';
        addButton.classList.remove('btn-secondary');
        addButton.classList.add('btn-primary');
    }
}

function hideProxyForm() {
    const formContainer = document.getElementById('new-proxy-form-container');
    const addButton = document.getElementById('add-proxy-btn');
    
    if (formContainer && addButton) {
        formContainer.classList.add('hidden');
        addButton.textContent = 'Add Proxy';
        addButton.classList.remove('btn-secondary');
        addButton.classList.add('btn-primary');
        newProxyForm.reset();
    }
}

// Route form toggle functions
function toggleRouteForm() {
    const formContainer = document.getElementById('new-route-form-container');
    const addButton = document.getElementById('add-route-btn');
    
    if (formContainer.classList.contains('hidden')) {
        formContainer.classList.remove('hidden');
        addButton.textContent = 'Cancel';
        addButton.classList.add('btn-secondary');
        addButton.classList.remove('btn-primary');
    } else {
        hideRouteForm();
    }
}

function hideRouteForm() {
    const formContainer = document.getElementById('new-route-form-container');
    const addButton = document.getElementById('add-route-btn');
    
    if (formContainer && addButton) {
        formContainer.classList.add('hidden');
        addButton.textContent = 'Add Route';
        addButton.classList.remove('btn-secondary');
        addButton.classList.add('btn-primary');
        newRouteForm?.reset();
    }
}

// Make hideRouteForm globally available
window.hideRouteForm = hideRouteForm;

// Certificate Management
async function loadCertificates() {
    const listContainer = document.getElementById('certificates-list');
    listContainer.innerHTML = '<div class="loading">Loading certificates...</div>';

    try {
        certificates = await api.getCertificates();
        
        if (certificates.length === 0) {
            listContainer.innerHTML = '<div class="empty-state">No certificates found. Create your first certificate!</div>';
            return;
        }

        listContainer.innerHTML = certificates.map(cert => {
            // Check if certificate is using staging
            const isStaging = cert.acme_directory_url && cert.acme_directory_url.includes('staging');
            
            return `
            <div class="certificate-card" data-cert-name="${cert.cert_name}">
                <div class="cert-header">
                    <h3>${cert.cert_name}</h3>
                    <span class="cert-status status-${cert.status}">${cert.status}</span>
                    ${isStaging ? '<span class="cert-staging">STAGING</span>' : ''}
                </div>
                <div class="cert-info">
                    <p><strong>Domains:</strong> ${cert.domains.join(', ')}</p>
                    <p><strong>Expires:</strong> ${formatDate(cert.expires_at)}</p>
                    ${isStaging ? '<p class="staging-warning">⚠️ This is a staging certificate (not trusted by browsers)</p>' : ''}
                </div>
                <div class="cert-actions">
                    <button class="btn btn-small" onclick="viewCertificate('${cert.cert_name}')">View Details</button>
                    <button class="btn btn-small btn-primary" onclick="renewCertificate('${cert.cert_name}')">Renew</button>
                    ${isStaging ? `<button class="btn btn-small btn-success" onclick="convertToProduction('${cert.cert_name}')">Convert to Production</button>` : ''}
                </div>
            </div>
            `;
        }).join('');

        // Check for any certificates being generated
        certificates.forEach(cert => {
            if (cert.status === 'pending') {
                pollCertificateStatus(cert.cert_name);
            }
        });
    } catch (error) {
        listContainer.innerHTML = `<div class="error">Error loading certificates: ${error.message}</div>`;
    }
}

async function handleNewCertificate(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const data = {
        cert_name: formData.get('cert_name'),
        domain: formData.get('domain'),
        acme_directory_url: formData.get('acme_directory_url')
    };

    try {
        const result = await api.createCertificate(data);
        showNotification('Certificate generation started', 'success');
        e.target.reset();
        hideCertificateForm();
        loadCertificates();
        
        // Start polling for status
        pollCertificateStatus(data.cert_name);
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function handleNewProxyTarget(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const data = {
        hostname: formData.get('hostname'),
        target_url: formData.get('target_url'),
        preserve_host_header: formData.get('preserve_host_header') === 'on',
        enable_http: formData.get('enable_http') === 'on',
        enable_https: formData.get('enable_https') === 'on',
        acme_directory_url: formData.get('acme_directory_url')
    };

    try {
        const result = await api.createProxyTarget(data);
        showNotification(`Proxy target ${data.hostname} created successfully`, 'success');
        
        if (result.certificate_status && result.certificate_status !== 'existing') {
            showNotification('Certificate generation started for proxy target', 'info');
            // Poll certificate status
            if (result.cert_name) {
                pollCertificateStatus(result.cert_name);
            }
        }
        
        e.target.reset();
        hideProxyForm();
        loadProxyTargets();
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function viewCertificate(certName) {
    try {
        const cert = await api.getCertificate(certName);
        
        certDetails.innerHTML = `
            <div class="cert-detail">
                <p><strong>Certificate Name:</strong> ${cert.cert_name}</p>
                <p><strong>Status:</strong> <span class="status-${cert.status}">${cert.status}</span></p>
                <p><strong>Domains:</strong></p>
                <ul>${cert.domains.map(d => `<li>${d}</li>`).join('')}</ul>
                <p><strong>Email:</strong> ${cert.email}</p>
                <p><strong>Issued:</strong> ${formatDate(cert.issued_at)}</p>
                <p><strong>Expires:</strong> ${formatDate(cert.expires_at)}</p>
                <p><strong>Fingerprint:</strong> <code>${cert.fingerprint || 'N/A'}</code></p>
                <p><strong>ACME Provider:</strong> ${cert.acme_directory_url}</p>
                
                <h4>Certificate Chain</h4>
                <textarea class="cert-pem" readonly>${cert.fullchain_pem || 'Not available'}</textarea>
                
                <h4>Private Key</h4>
                <textarea class="cert-pem" readonly>${cert.private_key_pem || 'Not available'}</textarea>
            </div>
        `;
        
        certModal.classList.remove('hidden');
    } catch (error) {
        showNotification(`Error loading certificate: ${error.message}`, 'error');
    }
}

async function renewCertificate(certName) {
    if (!confirm(`Are you sure you want to renew the certificate "${certName}"?`)) {
        return;
    }

    try {
        await api.renewCertificate(certName);
        showNotification('Certificate renewal started', 'success');
        loadCertificates();
        
        // Start polling for status
        pollCertificateStatus(certName);
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function convertToProduction(certName) {
    if (!confirm(`Are you sure you want to convert the certificate "${certName}" from staging to production?\n\nThis will generate a new trusted certificate.`)) {
        return;
    }

    try {
        await api.convertCertificateToProduction(certName);
        showNotification('Certificate conversion to production started', 'success');
        loadCertificates();
        
        // Start polling for status
        pollCertificateStatus(certName);
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function pollCertificateStatus(certName) {
    // Clear any existing interval for this certificate
    if (statusPollingIntervals.has(certName)) {
        clearInterval(statusPollingIntervals.get(certName));
    }

    const interval = setInterval(async () => {
        try {
            const status = await api.getCertificateStatus(certName);
            
            if (status.status === 'completed') {
                clearInterval(interval);
                statusPollingIntervals.delete(certName);
                showNotification(`Certificate "${certName}" generated successfully!`, 'success');
                loadCertificates();
            } else if (status.status === 'failed') {
                clearInterval(interval);
                statusPollingIntervals.delete(certName);
                showNotification(`Certificate "${certName}" generation failed: ${status.message}`, 'error');
                loadCertificates();
            }
            // Continue polling if status is 'in_progress'
        } catch (error) {
            clearInterval(interval);
            statusPollingIntervals.delete(certName);
            console.error('Error polling status:', error);
        }
    }, 5000); // Poll every 5 seconds

    statusPollingIntervals.set(certName, interval);
}

// Proxy Target Management
async function loadProxyTargets() {
    const listContainer = document.getElementById('proxy-list');
    listContainer.innerHTML = '<div class="loading">Loading proxy targets...</div>';
    
    try {
        proxyTargets = await api.getProxyTargets();
        
        if (proxyTargets.length === 0) {
            listContainer.innerHTML = '<p>No proxy targets configured. Create your first proxy target!</p>';
            return;
        }
        
        let html = '<div class="proxy-grid">';
        proxyTargets.forEach(target => {
            const status = target.enabled ? 'enabled' : 'disabled';
            const protocols = [];
            if (target.enable_http) protocols.push('HTTP');
            if (target.enable_https) protocols.push('HTTPS');
            const protocolStr = protocols.length > 0 ? protocols.join('/') : 'None';
            
            html += `
                <div class="proxy-card">
                    <h3>${target.hostname}</h3>
                    <p class="target-url">→ ${target.target_url}</p>
                    <p class="status ${status}">${status.toUpperCase()}</p>
                    <p class="protocols">Protocols: ${protocolStr}</p>
                    <p class="created">Created: ${formatDate(target.created_at)}</p>
                    ${target.cert_name ? `<p class="cert">Certificate: ${target.cert_name}</p>` : ''}
                    <div class="proxy-actions">
                        <button onclick="toggleProxyTarget('${target.hostname}', ${!target.enabled})" 
                                class="btn btn-sm">${target.enabled ? 'Disable' : 'Enable'}</button>
                        <button onclick="showProxyRouteModal('${target.hostname}')" 
                                class="btn btn-sm">Routes</button>
                        <button onclick="deleteProxyTarget('${target.hostname}')" 
                                class="btn btn-sm btn-danger">Delete</button>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        listContainer.innerHTML = html;
    } catch (error) {
        listContainer.innerHTML = `<p class="error">Failed to load proxy targets: ${error.message}</p>`;
    }
}

async function toggleProxyTarget(hostname, enable) {
    try {
        await api.updateProxyTarget(hostname, { enabled: enable });
        showNotification(`Proxy target ${hostname} ${enable ? 'enabled' : 'disabled'}`, 'success');
        loadProxyTargets();
    } catch (error) {
        showNotification(`Failed to update proxy target: ${error.message}`, 'error');
    }
}

async function deleteProxyTarget(hostname) {
    if (!confirm(`Are you sure you want to delete proxy target ${hostname}?`)) {
        return;
    }
    
    try {
        await api.deleteProxyTarget(hostname, true); // Delete certificate too
        showNotification(`Proxy target ${hostname} deleted`, 'success');
        loadProxyTargets();
    } catch (error) {
        showNotification(`Failed to delete proxy target: ${error.message}`, 'error');
    }
}

// Proxy Route Management
let currentProxyHostname = null;
let currentProxyRouteConfig = null;
let allRoutes = [];

async function showProxyRouteModal(hostname) {
    currentProxyHostname = hostname;
    document.getElementById('proxy-route-hostname').textContent = hostname;
    document.getElementById('proxy-route-modal').classList.remove('hidden');
    
    try {
        // Load proxy route configuration
        currentProxyRouteConfig = await api.getProxyRoutes(hostname);
        
        // Load all available routes
        allRoutes = await api.getRoutes();
        
        // Set route mode radio button
        const modeRadios = document.querySelectorAll('input[name="route-mode"]');
        modeRadios.forEach(radio => {
            radio.checked = radio.value === currentProxyRouteConfig.route_mode;
        });
        
        // Display routes
        displayProxyRoutes();
        
    } catch (error) {
        showNotification(`Failed to load route configuration: ${error.message}`, 'error');
    }
}

function closeProxyRouteModal() {
    document.getElementById('proxy-route-modal').classList.add('hidden');
    currentProxyHostname = null;
    currentProxyRouteConfig = null;
}

function updateRouteMode() {
    const selectedMode = document.querySelector('input[name="route-mode"]:checked').value;
    currentProxyRouteConfig.route_mode = selectedMode;
    displayProxyRoutes();
}

function displayProxyRoutes() {
    const container = document.getElementById('proxy-routes-list');
    const mode = currentProxyRouteConfig.route_mode;
    
    let html = '<h3>Available Routes</h3>';
    
    if (mode === 'none') {
        html += '<p class="info">No routes will apply in "None" mode - only hostname-based routing.</p>';
    } else {
        html += '<div class="route-checkboxes">';
        
        allRoutes.forEach(route => {
            const routeId = route.route_id;
            let checked = false;
            let disabled = false;
            
            if (mode === 'all') {
                // In 'all' mode, routes are checked by default unless disabled
                checked = !currentProxyRouteConfig.disabled_routes.includes(routeId);
            } else if (mode === 'selective') {
                // In 'selective' mode, only enabled routes are checked
                checked = currentProxyRouteConfig.enabled_routes.includes(routeId);
            }
            
            html += `
                <label class="route-checkbox-label">
                    <input type="checkbox" 
                           value="${routeId}" 
                           ${checked ? 'checked' : ''} 
                           onchange="toggleRouteSelection('${routeId}')">
                    <div class="route-info">
                        <strong>${escapeHtml(route.path_pattern)}</strong>
                        <span class="route-target">${route.target_type}: ${escapeHtml(route.target_value)}</span>
                        ${route.description ? `<span class="route-desc">${escapeHtml(route.description)}</span>` : ''}
                    </div>
                </label>
            `;
        });
        
        html += '</div>';
        
        if (mode === 'all') {
            html += '<p class="help-text">Unchecked routes will be disabled for this proxy.</p>';
        } else if (mode === 'selective') {
            html += '<p class="help-text">Only checked routes will apply to this proxy.</p>';
        }
    }
    
    container.innerHTML = html;
}

function toggleRouteSelection(routeId) {
    const mode = currentProxyRouteConfig.route_mode;
    
    if (mode === 'all') {
        // Toggle in disabled_routes
        const index = currentProxyRouteConfig.disabled_routes.indexOf(routeId);
        if (index === -1) {
            currentProxyRouteConfig.disabled_routes.push(routeId);
        } else {
            currentProxyRouteConfig.disabled_routes.splice(index, 1);
        }
    } else if (mode === 'selective') {
        // Toggle in enabled_routes
        const index = currentProxyRouteConfig.enabled_routes.indexOf(routeId);
        if (index === -1) {
            currentProxyRouteConfig.enabled_routes.push(routeId);
        } else {
            currentProxyRouteConfig.enabled_routes.splice(index, 1);
        }
    }
}

async function saveProxyRoutes() {
    try {
        const data = {
            route_mode: currentProxyRouteConfig.route_mode,
            enabled_routes: currentProxyRouteConfig.enabled_routes,
            disabled_routes: currentProxyRouteConfig.disabled_routes
        };
        
        await api.updateProxyRoutes(currentProxyHostname, data);
        showNotification(`Route configuration updated for ${currentProxyHostname}`, 'success');
        closeProxyRouteModal();
    } catch (error) {
        showNotification(`Failed to update route configuration: ${error.message}`, 'error');
    }
}

// Utility Functions
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function showNotification(message, type = 'info') {
    // Simple notification - you could enhance this with a toast library
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Add route form listener
    const newRouteForm = document.getElementById('new-route-form');
    if (newRouteForm) {
        newRouteForm.addEventListener('submit', handleNewRoute);
    }
    
    if (api.token) {
        // Test if token is still valid
        api.getCertificates()
            .then(() => showDashboard())
            .catch(() => showLogin());
    } else {
        showLogin();
    }
});

// Route Management
async function loadRoutes() {
    const listContainer = document.getElementById('routes-list');
    listContainer.innerHTML = '<div class="loading">Loading routes...</div>';
    
    try {
        routes = await api.getRoutes();
        displayRoutes(routes);
    } catch (error) {
        listContainer.innerHTML = `<div class="error">Error loading routes: ${error.message}</div>`;
    }
}

function displayRoutes(routes) {
    const listContainer = document.getElementById('routes-list');
    
    if (routes.length === 0) {
        listContainer.innerHTML = '<div class="empty-state">No routes configured</div>';
        return;
    }
    
    const routesHtml = routes.map(route => `
        <div class="route-item ${!route.enabled ? 'disabled' : ''}">
            <div class="route-info">
                <h3>${escapeHtml(route.path_pattern)}</h3>
                <div class="route-details">
                    <span class="badge">${route.target_type}: ${escapeHtml(route.target_value)}</span>
                    <span class="priority">Priority: ${route.priority}</span>
                    ${route.methods && route.methods.length > 0 ? 
                        `<span class="methods">${route.methods.join(', ')}</span>` : 
                        '<span class="methods">ALL</span>'
                    }
                    ${route.is_regex ? '<span class="badge regex">Regex</span>' : ''}
                    ${!route.enabled ? '<span class="badge disabled">Disabled</span>' : ''}
                </div>
                ${route.description ? `<p class="description">${escapeHtml(route.description)}</p>` : ''}
            </div>
            <div class="route-actions">
                ${`
                    <button class="btn btn-sm" onclick="toggleRoute('${route.route_id}', ${!route.enabled})">
                        ${route.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRoute('${route.route_id}')">
                        Delete
                    </button>
                `}
            </div>
        </div>
    `).join('');
    
    listContainer.innerHTML = routesHtml;
}

async function handleNewRoute(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    const routeData = {
        path_pattern: formData.get('path_pattern'),
        target_type: formData.get('target_type'),
        target_value: formData.get('target_value'),
        priority: parseInt(formData.get('priority')) || 50,
        methods: formData.get('methods') ? 
            formData.get('methods').split(',').map(m => m.trim().toUpperCase()).filter(m => m) : 
            null,
        is_regex: formData.get('is_regex') === 'on',
        description: formData.get('description'),
        enabled: formData.get('enabled') === 'on'
    };
    
    // Convert target_value to number if type is port
    if (routeData.target_type === 'port') {
        routeData.target_value = parseInt(routeData.target_value);
    }
    
    try {
        await api.createRoute(routeData);
        showNotification('Route created successfully', 'success');
        hideRouteForm();
        loadRoutes();
    } catch (error) {
        showNotification(`Error creating route: ${error.message}`, 'error');
    }
}

async function toggleRoute(routeId, enable) {
    try {
        await api.updateRoute(routeId, { enabled: enable });
        showNotification(`Route ${enable ? 'enabled' : 'disabled'} successfully`, 'success');
        loadRoutes();
    } catch (error) {
        showNotification(`Error updating route: ${error.message}`, 'error');
    }
}

async function deleteRoute(routeId) {
    if (!confirm('Are you sure you want to delete this route?')) {
        return;
    }
    
    try {
        await api.deleteRoute(routeId);
        showNotification('Route deleted successfully', 'success');
        loadRoutes();
    } catch (error) {
        showNotification(`Error deleting route: ${error.message}`, 'error');
    }
}

// Settings Management
async function loadTokenInfo() {    
    // Check if token exists
    if (!api.token) {        showNotification('Please login first', 'error');
        return;
    }
    
    try {        const response = await fetch('/token/info', {
            headers: {
                'Authorization': `Bearer ${api.token}`
            }
        });
        
        if (!response.ok) {            throw new Error('Failed to load token info');
        }        
        const data = await response.json();        
        // Update token info display
        document.getElementById('token-name').textContent = data.name || 'N/A';
        document.getElementById('token-preview').textContent = data.hash_preview || 'N/A';
        document.getElementById('current-email-value').textContent = data.cert_email || '(not set)';
        
        // Update email input placeholder
        const emailInput = document.getElementById('cert-email');
        if (emailInput && data.cert_email) {
            emailInput.placeholder = data.cert_email;
        }
    } catch (error) {
        console.error('Error loading token info:', error);
        showNotification('Failed to load token information', 'error');
    }
}

async function handleEmailUpdate(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const certEmail = formData.get('cert_email');
    
    if (!certEmail) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }
    
    try {
        const response = await fetch('/token/email', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${api.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cert_email: certEmail })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to update email');
        }
        
        const result = await response.json();
        showNotification(result.message || 'Email updated successfully', 'success');
        
        // Reload token info to show updated email
        loadTokenInfo();
        
        // Clear the form
        e.target.reset();
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// Helper function to escape HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Clean up intervals on page unload
window.addEventListener('beforeunload', () => {
    statusPollingIntervals.forEach(interval => clearInterval(interval));
});