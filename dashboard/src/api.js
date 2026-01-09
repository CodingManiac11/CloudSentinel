// API Service for CloudSentinel Backend
// Empty string means same origin - for full-stack deployment
const API_BASE = import.meta.env.VITE_API_URL || '';

export const api = {
    // Health check
    async health() {
        const res = await fetch(`${API_BASE}/health`);
        return res.json();
    },

    // Create a new scan
    async createScan(providers = ['aws', 'azure', 'kubernetes'], demoMode = true) {
        const res = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                providers,
                demo_mode: demoMode,
                include_predictions: true
            })
        });
        return res.json();
    },

    // Get scan status/results
    async getScan(scanId) {
        const res = await fetch(`${API_BASE}/scans/${scanId}`);
        return res.json();
    },

    // List all scans
    async listScans(limit = 10) {
        const res = await fetch(`${API_BASE}/scans?limit=${limit}`);
        return res.json();
    },

    // Get misconfigurations from a scan
    async getMisconfigurations(scanId, severity = null) {
        const url = severity
            ? `${API_BASE}/scans/${scanId}/misconfigurations?severity=${severity}`
            : `${API_BASE}/scans/${scanId}/misconfigurations`;
        const res = await fetch(url);
        return res.json();
    },

    // Get attack paths
    async getAttackPaths(scanId) {
        const res = await fetch(`${API_BASE}/scans/${scanId}/attack-paths`);
        return res.json();
    },

    // Create remediation
    async createRemediation(misconfigurationId, autoApply = true) {
        const res = await fetch(`${API_BASE}/remediations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                misconfiguration_id: misconfigurationId,
                auto_apply: autoApply
            })
        });
        return res.json();
    },

    // Execute remediation
    async executeRemediation(remediationId) {
        const res = await fetch(`${API_BASE}/remediations/${remediationId}/execute`, {
            method: 'POST'
        });
        return res.json();
    },

    // Get dashboard summary
    async getDashboardSummary() {
        const res = await fetch(`${API_BASE}/dashboard/summary`);
        return res.json();
    },

    // Poll scan until complete
    async pollScanUntilComplete(scanId, onProgress, maxAttempts = 30) {
        for (let i = 0; i < maxAttempts; i++) {
            const scan = await this.getScan(scanId);

            if (scan.status === 'completed') {
                return scan;
            }

            if (scan.status === 'failed') {
                throw new Error(scan.error || 'Scan failed');
            }

            // Report progress
            if (onProgress) {
                onProgress(Math.min(90, (i / maxAttempts) * 100));
            }

            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        throw new Error('Scan timed out');
    }
};

export default api;
