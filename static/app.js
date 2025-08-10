class SecurityHeaderAnalyzer {
    constructor() {
        this.form = document.getElementById('analyzeForm');
        this.urlInput = document.getElementById('urlInput');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.forceRefresh = document.getElementById('forceRefresh');
        this.loadingIndicator = document.getElementById('loadingIndicator');
        this.resultsSection = document.getElementById('resultsSection');
        this.errorAlert = document.getElementById('errorAlert');
        this.shareBtn = document.getElementById('shareBtn');
        this.currentAnalyzedUrl = null;
        this.isLoading = false;

        this.initializeEventListeners();
        this.initializeSmoothOutlineAnimation();
        this.checkForSharedUrl();
    }

    initializeEventListeners() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.analyzeUrl();
        });
    }

    // Smooth outline animation (JS rAF, time-based easing) on native outline
    initializeSmoothOutlineAnimation() {
        const cards = document.querySelectorAll('.card');

        const easeInOutCubic = (t) => (t < 0.5)
            ? 4 * t * t * t
            : 1 - Math.pow(-2 * t + 2, 3) / 2;

        cards.forEach((el) => {
            // Baseline visual (balanced)
            const baseW = 1.5;
            const baseA = 0.7;
            const hoverW = 3;
            const hoverA = 1;

            el.style.outlineStyle = 'solid';
            el.style.outlineOffset = '-1px';
            el.style.outlineWidth = baseW + 'px';
            el.style.outlineColor = `rgba(206, 212, 218, ${baseA})`;

            let rafId = null;
            let lastW = baseW;
            let lastA = baseA;
            let anim = null; // {start, duration, fromW, fromA, toW, toA}

            const step = (now) => {
                if (!anim) { rafId = null; return; }
                const t = Math.min(1, (now - anim.start) / anim.duration);
                const e = easeInOutCubic(t);
                const w = anim.fromW + (anim.toW - anim.fromW) * e;
                const a = anim.fromA + (anim.toA - anim.fromA) * e;

                lastW = w; lastA = a;
                el.style.outlineWidth = w + 'px';
                el.style.outlineColor = `rgba(206, 212, 218, ${a})`;

                if (t < 1) {
                    rafId = requestAnimationFrame(step);
                } else {
                    rafId = null;
                }
            };

            const animateTo = (toW, toA, duration = 150) => {
                anim = {
                    start: performance.now(),
                    duration,
                    fromW: lastW,
                    fromA: lastA,
                    toW,
                    toA
                };

                if (!rafId) rafId = requestAnimationFrame(step);
            };

            // Hover/focus: fast in, smooth out
            el.addEventListener('mouseenter', () => animateTo(hoverW, hoverA, 140));
            el.addEventListener('focusin', () => animateTo(hoverW, hoverA, 140));
            el.addEventListener('mouseleave', () => animateTo(baseW, baseA, 160));
            el.addEventListener('focusout', () => animateTo(baseW, baseA, 160));
        });
    }

    async analyzeUrl() {
        const url = this.urlInput.value.trim();
        if (!url) {
            this.showError('Please enter a URL to analyze');
            return;
        }

        if (this.isLoading) {
            return;
        }

        this.showLoading(true);
        this.hideError();
        this.hideResults();

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: url,
                    force_refresh: this.forceRefresh.checked
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.displayResults(data);
                this.updateShareLink(data.url || url);
            } else {
                this.showError(data.message || 'Analysis failed');
            }
        } catch (error) {
            this.showError('Network error: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    displayResults(data) {
        if (data.url && this.urlInput.value.trim() !== data.url) {
            this.urlInput.value = data.url;
        }

        const summaryText = document.getElementById('summaryText');
        summaryText.textContent = `Analysis completed for ${data.url}`;
        const cacheStatus = document.getElementById('cacheStatus');
        cacheStatus.textContent = data.cached ? 'Cached' : 'Fresh';
        cacheStatus.className = `badge ${data.cached ? 'bg-info' : 'bg-success'}`;

        const securityGrade = document.getElementById('securityGrade');
        const letter = (data.grade || '?').toString().toUpperCase();
        const pct = (data.score !== undefined && data.score !== null) ? `${data.score}%` : '0%';
        securityGrade.className = `security-grade ${this.getGradeClass(data.grade)}`;
        securityGrade.innerHTML = `
            <div class="grade-wrap">
                <span class="grade-letter">${letter}</span>
                <span class="grade-percent">${pct}</span>
            </div>
        `;

        this.displayPresentHeaders(data.security_headers || {});
        this.displayMissingHeaders(data.missing_headers || []);
        this.displayWarnings(data.warnings || []);
        this.displayRawData(data);
        this.showResults();
        setTimeout(() => {
            document.getElementById('resultsSection').scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }, 100);
    }

    displayPresentHeaders(headers) {
        const container = document.getElementById('presentHeaders');
        container.innerHTML = '';

        const presentHeaders = Object.entries(headers).filter(([_, info]) => info.present);

        if (presentHeaders.length === 0) {
            container.innerHTML = '<p class="text-muted">No security headers detected</p>';
            return;
        }

        presentHeaders.forEach(([name, info]) => {
            const headerElement = document.createElement('div');
            headerElement.className = 'mb-3 p-3 border rounded';

            const statusClass = this.getHeaderStatusClass(info.status);

            headerElement.innerHTML = `
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <h6 class="mb-0">${this.escapeHtml(name)}</h6>
                    <span class="badge ${statusClass}">${info.status || 'present'}</span>
                </div>
                <div class="small text-muted mb-2">
                    <strong>Value:</strong> <code>${this.escapeHtml(info.value || 'N/A')}</code>
                </div>
                ${info.recommendation ? `
                    <div class="small text-info">
                        <i class="fas fa-lightbulb me-1"></i>
                        ${this.escapeHtml(info.recommendation)}
                    </div>
                ` : ''}
            `;

            container.appendChild(headerElement);
        });
    }

    displayMissingHeaders(missingHeaders) {
        const container = document.getElementById('missingHeaders');
        container.innerHTML = '';

        if (missingHeaders.length === 0) {
            container.innerHTML = '<p class="text-success">All important security headers are present!</p>';
            return;
        }

        missingHeaders.forEach(header => {
            const headerElement = document.createElement('div');
            headerElement.className = 'mb-2 p-2 bg-warning bg-opacity-10 border border-warning rounded';
            headerElement.innerHTML = `
                <div class="d-flex align-items-center">
                    <i class="fas fa-exclamation-triangle text-warning me-2"></i>
                    <span>${this.escapeHtml(header)}</span>
                </div>
            `;
            container.appendChild(headerElement);
        });
    }

    displayWarnings(warnings) {
        const warningsSection = document.getElementById('warningsSection');
        const warningsList = document.getElementById('warningsList');

        if (warnings.length === 0) {
            warningsSection.style.display = 'none';
            return;
        }

        warningsSection.style.display = 'block';
        warningsList.innerHTML = '';

        warnings.forEach(warning => {
            const warningElement = document.createElement('div');
            warningElement.className = 'alert alert-warning mb-2';
            warningElement.style.color = 'var(--bs-body-color)';
            warningElement.innerHTML = `
                <div class="d-flex align-items-start">
                    <i class="fas fa-exclamation-triangle text-warning me-2 mt-1"></i>
                    <div>
                        <strong>${this.escapeHtml(warning.header || 'General')}:</strong>
                        ${this.escapeHtml(warning.message)}
                    </div>
                </div>
            `;
            warningsList.appendChild(warningElement);
        });
    }

    displayRawData(data) {
        const rawDataElement = document.getElementById('rawData');
        rawDataElement.textContent = JSON.stringify(data, null, 2);
        this.currentRawData = data;
    }

    getGradeClass(grade) {
        switch (grade?.toUpperCase()) {
            case 'A': return 'grade-a';
            case 'B': return 'grade-b';
            case 'C': return 'grade-c';
            case 'D': return 'grade-d';
            case 'F': return 'grade-f';
            default: return 'grade-unknown';
        }
    }

    getHeaderStatusClass(status) {
        switch (status?.toLowerCase()) {
            case 'good':
            case 'present':
                return 'bg-success';
            case 'warning':
                return 'bg-warning text-dark';
            case 'error':
            case 'bad':
                return 'bg-danger';
            default:
                return 'bg-secondary';
        }
    }

    showLoading(show) {
        this.isLoading = show;
        this.loadingIndicator.style.display = show ? 'block' : 'none';
        this.analyzeBtn.disabled = show;
        this.analyzeBtn.setAttribute('aria-busy', show ? 'true' : 'false');
        this.urlInput.disabled = show;
        this.forceRefresh.disabled = show;

        if (show) {
            this.analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
        } else {
            this.analyzeBtn.innerHTML = '<i class="fas fa-search me-2"></i>Analyze';
        }
    }

    showResults() {
        this.resultsSection.style.display = 'block';
        const anchor = document.getElementById('results');
        if (anchor) {
            anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
            this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    hideResults() {
        this.resultsSection.style.display = 'none';
    }

    showError(message) {
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.textContent = message;
        this.errorAlert.style.display = 'block';
        this.errorAlert.scrollIntoView({ behavior: 'smooth' });
    }

    hideError() {
        this.errorAlert.style.display = 'none';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    checkForSharedUrl() {
        if (this.urlInput.value.trim()) {
            this.analyzeUrl();
        }
    }

    updateShareLink(url) {
        this.currentAnalyzedUrl = url;
        this.shareBtn.style.display = 'inline-block';
        // this.copyShareLinkToClipboard();
    }

    copyShareLinkToClipboard() {
        if (!this.currentAnalyzedUrl) return;

        const shareUrl = `${window.location.origin}/?url=${encodeURIComponent(this.currentAnalyzedUrl)}`;

        navigator.clipboard.writeText(shareUrl).then(() => {
            const originalText = this.shareBtn.innerHTML;
            this.shareBtn.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
            this.shareBtn.classList.remove('btn-outline-primary');
            this.shareBtn.classList.add('btn-success');

            setTimeout(() => {
                this.shareBtn.innerHTML = originalText;
                this.shareBtn.classList.remove('btn-success');
                this.shareBtn.classList.add('btn-outline-primary');
            }, 2000);
        }).catch(() => {
            const shareUrl = `${window.location.origin}/?url=${encodeURIComponent(this.currentAnalyzedUrl)}`;
            prompt('Copy this share link:', shareUrl);
        });
    }
}

async function checkHealth() {
    try {
        const response = await fetch('/api/health');
        const data = await response.json();

        const statusClass = data.status === 'healthy' ? 'success' : 'danger';
        const message = data.status === 'healthy'
            ? `System is healthy. Humble: ${data.services.humble}`
            : `System is unhealthy: ${data.error}`;

        showToast(message, statusClass);
    } catch (error) {
        showToast('Failed to check health: ' + error.message, 'danger');
    }
}

async function clearCache() {
    try {
        const response = await fetch('/api/cache/clear', { method: 'POST' });
        const data = await response.json();

        if (response.ok) {
            showToast('Cache cleared successfully', 'success');
        } else {
            showToast('Failed to clear cache: ' + data.message, 'danger');
        }
    } catch (error) {
        showToast('Failed to clear cache: ' + error.message, 'danger');
    }
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;

    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success');
    }).catch(err => {
        showToast('Failed to copy: ' + err.message, 'danger');
    });
}

function downloadJson() {
    if (!window.analyzer || !window.analyzer.currentRawData) {
        showToast('No data available for download', 'warning');
        return;
    }

    const data = window.analyzer.currentRawData;
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `security-analysis-${data.url ? data.url.replace(/[^a-zA-Z0-9]/g, '-') : 'unknown'}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('JSON file downloaded', 'success');
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    toast.style.cssText = 'position: fixed; top: 20px; right: -350px; z-index: 9999; min-width: 320px; max-width: 400px; transition: right 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);';
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas ${getToastIcon(type)} me-2"></i>
            <span>${message}</span>
            <button type="button" class="toast-close" onclick="hideToast(this.parentElement.parentElement)">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;

    document.body.appendChild(toast);
    toast.offsetHeight;

    setTimeout(() => {
        toast.style.right = '20px';
    }, 50);

    setTimeout(() => {
        hideToast(toast);
    }, 4000);
}

function hideToast(toast) {
    if (!toast || !toast.parentNode) return;

    toast.style.right = '-350px';

    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 400);
}

function getToastIcon(type) {
    switch (type) {
        case 'success': return 'fa-check-circle';
        case 'danger': return 'fa-exclamation-circle';
        case 'warning': return 'fa-exclamation-triangle';
        default: return 'fa-info-circle';
    }
}

function copyShareLink() {
    if (window.analyzer) {
        window.analyzer.copyShareLinkToClipboard();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.analyzer = new SecurityHeaderAnalyzer();
});
