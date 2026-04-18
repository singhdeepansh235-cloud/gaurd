/**
 * Sentinal-Fuzz Web Interface — Global JavaScript
 *
 * Toast notifications, mobile navigation, keyboard shortcuts,
 * and shared utility functions.
 */

// ── Mobile Navigation ─────────────────────────────────────────────

function toggleMobileNav() {
    const hamburger = document.getElementById('nav-hamburger');
    const navLinks = document.getElementById('nav-links');
    if (hamburger && navLinks) {
        hamburger.classList.toggle('active');
        navLinks.classList.toggle('open');
    }
}

// Close mobile nav when clicking a link
document.addEventListener('click', (e) => {
    const link = e.target.closest('.nav-links a');
    if (link) {
        const navLinks = document.getElementById('nav-links');
        const hamburger = document.getElementById('nav-hamburger');
        if (navLinks) navLinks.classList.remove('open');
        if (hamburger) hamburger.classList.remove('active');
    }
});

// ── Toast Notification System ─────────────────────────────────────

function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const icons = {
        success: '✓',
        error: '✗',
        info: 'i',
    };

    toast.innerHTML = `
        <span style="font-weight:700">${icons[type] || 'i'}</span>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 200);
    }, duration);

    toast.addEventListener('click', () => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 200);
    });
}

// ── HTML Escaping ─────────────────────────────────────────────────

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ── Navigation Active State ───────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (path === href || (href !== '/' && path.startsWith(href))) {
            link.classList.add('active');
        } else if (href === '/' && path === '/') {
            link.classList.add('active');
        }
    });
});

// ── Keyboard Shortcuts ────────────────────────────────────────────

document.addEventListener('keydown', (e) => {
    // Ctrl+K → Focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const search = document.querySelector(
            '.form-input[type="text"][placeholder*="Search"], ' +
            '#quick-scan-url, #search-findings, #search-scans'
        );
        if (search) search.focus();
    }

    // Escape → Close expanded finding cards
    if (e.key === 'Escape') {
        document.querySelectorAll('.finding-card.expanded').forEach(card => {
            card.classList.remove('expanded');
        });
        // Also close mobile nav
        const navLinks = document.getElementById('nav-links');
        const hamburger = document.getElementById('nav-hamburger');
        if (navLinks) navLinks.classList.remove('open');
        if (hamburger) hamburger.classList.remove('active');
    }
});

// ── Utility Functions ─────────────────────────────────────────────

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

function formatDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(1) + 's';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}m ${secs}s`;
}

// ── Auto-refresh dashboard if active scans exist ──────────────────

(function autoRefreshDashboard() {
    const activeIndicators = document.querySelectorAll('.scan-running-indicator');
    if (activeIndicators.length > 0 && window.location.pathname === '/') {
        setTimeout(() => window.location.reload(), 10000);
    }
})();
