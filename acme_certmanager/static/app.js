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
}

// Initialize API client
const api = new CertificateAPI();

// UI State Management
let currentTab = 'certificates';
let certificates = [];
let statusPollingIntervals = new Map();

// DOM Elements
const loginSection = document.getElementById('login-section');
const dashboardSection = document.getElementById('dashboard-section');
const loginForm = document.getElementById('login-form');
const newCertForm = document.getElementById('new-certificate-form');
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

    if (tab === 'certificates') {
        loadCertificates();
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
        email: formData.get('email'),
        acme_directory_url: formData.get('acme_directory_url')
    };

    try {
        const result = await api.createCertificate(data);
        showNotification('Certificate generation started', 'success');
        e.target.reset();
        switchTab('certificates');
        
        // Start polling for status
        pollCertificateStatus(data.cert_name);
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

// Clean up intervals on page unload
window.addEventListener('beforeunload', () => {
    statusPollingIntervals.forEach(interval => clearInterval(interval));
});