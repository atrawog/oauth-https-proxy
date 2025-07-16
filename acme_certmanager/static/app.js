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
}

// Initialize API client
const api = new CertificateAPI();

// UI State Management
let currentTab = 'certificates';
let certificates = [];
let proxyTargets = [];
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

    if (tab === 'certificates') {
        loadCertificates();
    } else if (tab === 'proxies') {
        loadProxyTargets();
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
    }
}

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

        listContainer.innerHTML = certificates.map(cert => `
            <div class="certificate-card" data-cert-name="${cert.cert_name}">
                <div class="cert-header">
                    <h3>${cert.cert_name}</h3>
                    <span class="cert-status status-${cert.status}">${cert.status}</span>
                </div>
                <div class="cert-info">
                    <p><strong>Domains:</strong> ${cert.domains.join(', ')}</p>
                    <p><strong>Expires:</strong> ${formatDate(cert.expires_at)}</p>
                </div>
                <div class="cert-actions">
                    <button class="btn btn-small" onclick="viewCertificate('${cert.cert_name}')">View Details</button>
                    <button class="btn btn-small btn-primary" onclick="renewCertificate('${cert.cert_name}')">Renew</button>
                </div>
            </div>
        `).join('');

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
        preserve_host_header: formData.get('preserve_host_header') === 'on'
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
            html += `
                <div class="proxy-card">
                    <h3>${target.hostname}</h3>
                    <p class="target-url">→ ${target.target_url}</p>
                    <p class="status ${status}">${status.toUpperCase()}</p>
                    <p class="created">Created: ${formatDate(target.created_at)}</p>
                    ${target.cert_name ? `<p class="cert">Certificate: ${target.cert_name}</p>` : ''}
                    <div class="proxy-actions">
                        <button onclick="toggleProxyTarget('${target.hostname}', ${!target.enabled})" 
                                class="btn btn-sm">${target.enabled ? 'Disable' : 'Enable'}</button>
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
    if (api.token) {
        // Test if token is still valid
        api.getCertificates()
            .then(() => showDashboard())
            .catch(() => showLogin());
    } else {
        showLogin();
    }
});

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

// Clean up intervals on page unload
window.addEventListener('beforeunload', () => {
    statusPollingIntervals.forEach(interval => clearInterval(interval));
});