import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, Activity, Zap, Search,
  Menu, X, ChevronRight, Lock, Server, Cloud,
  Database, Network, Terminal, CheckCircle, Filter,
  RefreshCw, Eye, Clock, ArrowRight, XCircle,
  Play, Pause, RotateCcw, ChevronDown, FileText,
  GitBranch, Target, Crosshair, AlertCircle, Settings,
  Wifi, WifiOff, Globe
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  PieChart, Pie, Cell, BarChart, Bar, Legend
} from 'recharts';
import api from './api';

// --- Initial Mock Data ---
const initialMockData = {
  grade: 'D',
  score: 76,
  scanned: 1452,
  issues: { critical: 4, high: 8, medium: 15, low: 22 },
  history: [
    { day: 'Mon', score: 65 }, { day: 'Tue', score: 68 },
    { day: 'Wed', score: 72 }, { day: 'Thu', score: 70 },
    { day: 'Fri', score: 76 }, { day: 'Sat', score: 82 },
    { day: 'Sun', score: 76 },
  ],
  categories: [
    { subject: 'IAM', A: 120, fullMark: 150 },
    { subject: 'Storage', A: 98, fullMark: 150 },
    { subject: 'Network', A: 86, fullMark: 150 },
    { subject: 'Compute', A: 99, fullMark: 150 },
    { subject: 'K8s', A: 85, fullMark: 150 },
    { subject: 'Data', A: 65, fullMark: 150 },
  ],
};

const initialFindings = [
  { id: 1, title: 'Public S3 Bucket with PII', resource: 'acme-customer-data', severity: 'critical', type: 'Storage', fixed: false, timestamp: '2 hours ago' },
  { id: 2, title: 'Root Access in Container', resource: 'payment-service-pod', severity: 'critical', type: 'K8s', fixed: false, timestamp: '3 hours ago' },
  { id: 3, title: 'Unencrypted RDS Instance', resource: 'prod-db-01', severity: 'high', type: 'Database', fixed: false, timestamp: '5 hours ago' },
  { id: 4, title: 'Open Security Group 0.0.0.0/0', resource: 'sg-web-frontal', severity: 'high', type: 'Network', fixed: false, timestamp: '6 hours ago' },
  { id: 5, title: 'IAM User with Stale Key', resource: 'user-jenkins-bot', severity: 'medium', type: 'IAM', fixed: false, timestamp: '8 hours ago' },
  { id: 6, title: 'Unused EBS Volume', resource: 'vol-0a1b2c3d', severity: 'low', type: 'Storage', fixed: false, timestamp: '12 hours ago' },
  { id: 7, title: 'Missing CloudTrail Logging', resource: 'us-east-1', severity: 'high', type: 'Logging', fixed: false, timestamp: '1 day ago' },
  { id: 8, title: 'Weak Password Policy', resource: 'iam-policy-default', severity: 'medium', type: 'IAM', fixed: false, timestamp: '1 day ago' },
];

const attackPaths = [
  { id: 1, severity: 'critical', name: 'External Access → S3 → Data Exfiltration', steps: 4, assets: 12 },
  { id: 2, severity: 'critical', name: 'Compromised EC2 → IAM Escalation → Admin', steps: 6, assets: 8 },
  { id: 3, severity: 'high', name: 'Public Lambda → VPC Access → Database', steps: 3, assets: 5 },
  { id: 4, severity: 'high', name: 'Container Escape → Node Compromise', steps: 5, assets: 15 },
  { id: 5, severity: 'medium', name: 'Stale Credentials → Lateral Movement', steps: 4, assets: 7 },
];

const logsData = [
  { id: 1, type: 'alert', message: 'Critical finding detected: Public S3 Bucket', source: 'scanner', timestamp: '18:35:22' },
  { id: 2, type: 'info', message: 'Scan completed for region us-east-1', source: 'scheduler', timestamp: '18:32:15' },
  { id: 3, type: 'success', message: 'Auto-remediation applied: Security Group updated', source: 'remediation', timestamp: '18:28:44' },
  { id: 4, type: 'warning', message: 'Rate limit approaching for AWS API calls', source: 'connector', timestamp: '18:25:01' },
  { id: 5, type: 'alert', message: 'New attack path identified with critical severity', source: 'analyzer', timestamp: '18:20:33' },
  { id: 6, type: 'info', message: 'Agent heartbeat received from 45 nodes', source: 'agent-manager', timestamp: '18:15:00' },
  { id: 7, type: 'success', message: 'Compliance report generated successfully', source: 'reporter', timestamp: '18:10:22' },
  { id: 8, type: 'info', message: 'Starting scheduled security scan', source: 'scheduler', timestamp: '18:00:00' },
];

const COLORS = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#06b6d4',
  low: '#10b981'
};

// --- Toast Notification Component ---
const Toast = ({ notifications, onDismiss }) => (
  <div className="fixed top-24 right-8 z-50 space-y-3">
    <AnimatePresence>
      {notifications.map((notif) => (
        <motion.div
          key={notif.id}
          initial={{ opacity: 0, x: 100, scale: 0.8 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          exit={{ opacity: 0, x: 100, scale: 0.8 }}
          className={`flex items-center gap-3 px-4 py-3 rounded-xl border backdrop-blur-md shadow-lg min-w-[300px] ${notif.type === 'success' ? 'bg-[rgba(16,185,129,0.15)] border-[rgba(16,185,129,0.3)]' :
            notif.type === 'error' ? 'bg-[rgba(239,68,68,0.15)] border-[rgba(239,68,68,0.3)]' :
              'bg-[rgba(139,92,246,0.15)] border-[rgba(139,92,246,0.3)]'
            }`}
        >
          {notif.type === 'success' ? <CheckCircle size={18} className="text-[var(--neon-green)]" /> :
            notif.type === 'error' ? <XCircle size={18} className="text-[#ef4444]" /> :
              <AlertCircle size={18} className="text-[var(--neon-purple)]" />}
          <span className="flex-1 text-sm font-medium">{notif.message}</span>
          <button onClick={() => onDismiss(notif.id)} className="text-[var(--text-secondary)] hover:text-white">
            <X size={14} />
          </button>
        </motion.div>
      ))}
    </AnimatePresence>
  </div>
);

// --- Search Modal Component ---
const SearchModal = ({ isOpen, onClose, onNavigate, findings }) => {
  const [query, setQuery] = useState('');

  const filteredFindings = findings.filter(f =>
    f.title.toLowerCase().includes(query.toLowerCase()) ||
    f.resource.toLowerCase().includes(query.toLowerCase())
  );

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'attacks', label: 'Attack Paths', icon: Network },
    { id: 'response', label: 'Response', icon: Search },
    { id: 'logs', label: 'Logs', icon: Terminal },
  ];

  const filteredTabs = tabs.filter(t =>
    t.label.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-start justify-center pt-32 bg-[rgba(0,0,0,0.7)] backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: -20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -20, scale: 0.95 }}
        className="w-full max-w-2xl glass-card p-0 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 p-4 border-b border-[var(--glass-border)]">
          <Search size={20} className="text-[var(--neon-purple)]" />
          <input
            type="text"
            placeholder="Search findings, resources, or navigate..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent border-none outline-none text-white placeholder:text-[var(--text-secondary)]"
            autoFocus
          />
          <kbd className="px-2 py-1 text-xs bg-[rgba(255,255,255,0.05)] rounded border border-[var(--glass-border)] text-[var(--text-dim)]">ESC</kbd>
        </div>

        <div className="max-h-96 overflow-y-auto p-2">
          {query && (
            <>
              {filteredTabs.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wider px-3 py-2">Navigate to</p>
                  {filteredTabs.map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => { onNavigate(tab.id); onClose(); }}
                      className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[rgba(255,255,255,0.05)] transition-colors"
                    >
                      <tab.icon size={16} className="text-[var(--neon-purple)]" />
                      <span>{tab.label}</span>
                      <ArrowRight size={14} className="ml-auto text-[var(--text-dim)]" />
                    </button>
                  ))}
                </div>
              )}

              {filteredFindings.length > 0 && (
                <div>
                  <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wider px-3 py-2">Findings</p>
                  {filteredFindings.slice(0, 5).map(finding => (
                    <button
                      key={finding.id}
                      onClick={() => { onNavigate('findings'); onClose(); }}
                      className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[rgba(255,255,255,0.05)] transition-colors"
                    >
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[finding.severity] }} />
                      <div className="flex-1 text-left">
                        <p className="text-sm font-medium">{finding.title}</p>
                        <p className="text-xs text-[var(--text-dim)] font-mono">{finding.resource}</p>
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {filteredTabs.length === 0 && filteredFindings.length === 0 && (
                <div className="text-center py-8 text-[var(--text-secondary)]">
                  No results found for "{query}"
                </div>
              )}
            </>
          )}

          {!query && (
            <div className="text-center py-8 text-[var(--text-secondary)]">
              Start typing to search...
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
};

// --- Components ---
const SidebarItem = ({ icon: Icon, label, active, onClick }) => (
  <motion.button
    whileHover={{ x: 5, backgroundColor: 'rgba(255, 255, 255, 0.05)' }}
    whileTap={{ scale: 0.95 }}
    onClick={onClick}
    className={`w-full flex items-center gap-4 p-4 rounded-xl transition-all duration-300 ${active
      ? 'bg-gradient-to-r from-[rgba(139,92,246,0.2)] to-transparent border-l-2 border-[var(--neon-purple)] text-white'
      : 'text-[var(--text-secondary)] hover:text-white'
      }`}
  >
    <Icon size={20} className={active ? 'text-[var(--neon-purple)]' : ''} />
    <span className="font-medium tracking-wide">{label}</span>
  </motion.button>
);

const StatCard = ({ title, value, subtext, icon: Icon, color, delay, onClick }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5, delay }}
    className={`glass-card p-6 flex flex-col justify-between h-40 ${onClick ? 'cursor-pointer' : ''}`}
    onClick={onClick}
    whileHover={onClick ? { scale: 1.02 } : {}}
  >
    <div className="flex justify-between items-start">
      <div className="p-3 rounded-lg" style={{ backgroundColor: `${color}20` }}>
        <Icon size={24} style={{ color }} />
      </div>
      {Icon === Activity && (
        <span className="text-xs font-mono text-[var(--neon-green)] flex items-center gap-1">
          +12% <ChevronRight size={10} className="-rotate-90" />
        </span>
      )}
    </div>
    <div>
      <h3 className="text-[var(--text-secondary)] text-sm font-medium mb-1">{title}</h3>
      <div className="text-3xl font-bold font-mono tracking-tighter" style={{ textShadow: `0 0 20px ${color}40` }}>
        {value}
      </div>
      {subtext && <p className="text-xs text-[var(--text-dim)] mt-1">{subtext}</p>}
    </div>
  </motion.div>
);

const SeverityPill = ({ severity }) => (
  <span
    className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border"
    style={{
      borderColor: `${COLORS[severity]}40`,
      backgroundColor: `${COLORS[severity]}10`,
      color: COLORS[severity],
      boxShadow: `0 0 10px ${COLORS[severity]}20`
    }}
  >
    {severity}
  </span>
);

// --- Findings View ---
const FindingsView = ({ findings, onFix, fixingId, filter, setFilter }) => {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

  const filteredFindings = filter === 'all'
    ? findings
    : findings.filter(f => f.severity === filter);

  const sortedFindings = [...filteredFindings].sort((a, b) =>
    severityOrder[a.severity] - severityOrder[b.severity]
  );

  const stats = {
    critical: findings.filter(f => f.severity === 'critical' && !f.fixed).length,
    high: findings.filter(f => f.severity === 'high' && !f.fixed).length,
    medium: findings.filter(f => f.severity === 'medium' && !f.fixed).length,
    low: findings.filter(f => f.severity === 'low' && !f.fixed).length,
    fixed: findings.filter(f => f.fixed).length,
  };

  return (
    <div className="space-y-6">
      {/* Stats Bar */}
      <div className="flex gap-4 flex-wrap">
        {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${filter === sev
              ? 'bg-[var(--neon-purple)] text-white shadow-[0_0_20px_rgba(139,92,246,0.4)]'
              : 'bg-[rgba(255,255,255,0.05)] text-[var(--text-secondary)] hover:text-white'
              }`}
          >
            {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
            {sev !== 'all' && (
              <span className="ml-2 px-2 py-0.5 rounded-full text-xs" style={{
                backgroundColor: `${COLORS[sev]}20`,
                color: COLORS[sev]
              }}>
                {stats[sev]}
              </span>
            )}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2 text-sm text-[var(--neon-green)]">
          <CheckCircle size={16} />
          {stats.fixed} Fixed
        </div>
      </div>

      {/* Findings Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card overflow-hidden"
      >
        <table className="w-full text-sm">
          <thead className="bg-[rgba(255,255,255,0.02)]">
            <tr className="text-left text-[var(--text-secondary)] text-xs uppercase tracking-wider">
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Finding</th>
              <th className="px-6 py-4">Resource</th>
              <th className="px-6 py-4">Type</th>
              <th className="px-6 py-4">Time</th>
              <th className="px-6 py-4">Action</th>
            </tr>
          </thead>
          <tbody>
            {sortedFindings.map((item) => (
              <motion.tr
                key={item.id}
                layout
                className={`border-t border-[rgba(255,255,255,0.02)] transition-colors ${item.fixed ? 'opacity-50' : 'hover:bg-[rgba(255,255,255,0.02)]'
                  }`}
              >
                <td className="px-6 py-4">
                  <SeverityPill severity={item.severity} />
                </td>
                <td className="px-6 py-4 font-medium">
                  {item.fixed && <span className="text-[var(--neon-green)] mr-2">✓</span>}
                  {item.title}
                </td>
                <td className="px-6 py-4 text-[var(--text-secondary)] font-mono text-xs">{item.resource}</td>
                <td className="px-6 py-4 text-[var(--text-dim)]">{item.type}</td>
                <td className="px-6 py-4 text-[var(--text-dim)] text-xs">{item.timestamp}</td>
                <td className="px-6 py-4">
                  {item.fixed ? (
                    <span className="flex items-center gap-2 text-[var(--neon-green)] text-sm">
                      <CheckCircle size={14} /> Fixed
                    </span>
                  ) : (
                    <button
                      onClick={() => onFix(item.id)}
                      disabled={fixingId === item.id}
                      className="glow-btn px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 disabled:opacity-50"
                    >
                      {fixingId === item.id ? (
                        <><RefreshCw size={12} className="animate-spin" /> Fixing...</>
                      ) : (
                        <><Zap size={12} /> Auto-Fix</>
                      )}
                    </button>
                  )}
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </motion.div>
    </div>
  );
};

// --- Attack Paths View ---
const AttackPathsView = () => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="glass-card p-6 text-center">
        <div className="text-4xl font-bold text-[#ef4444] mb-2">{attackPaths.filter(p => p.severity === 'critical').length}</div>
        <div className="text-[var(--text-secondary)] text-sm">Critical Paths</div>
      </div>
      <div className="glass-card p-6 text-center">
        <div className="text-4xl font-bold text-[#f59e0b] mb-2">{attackPaths.filter(p => p.severity === 'high').length}</div>
        <div className="text-[var(--text-secondary)] text-sm">High Risk Paths</div>
      </div>
      <div className="glass-card p-6 text-center">
        <div className="text-4xl font-bold text-[var(--neon-blue)] mb-2">47</div>
        <div className="text-[var(--text-secondary)] text-sm">Assets at Risk</div>
      </div>
    </div>

    <div className="glass-card p-6">
      <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
        <GitBranch size={18} className="text-[var(--neon-pink)]" />
        Identified Attack Paths
      </h3>
      <div className="space-y-4">
        {attackPaths.map((path, idx) => (
          <motion.div
            key={path.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="flex items-center gap-4 p-4 rounded-xl bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.05)] hover:border-[var(--neon-purple)] transition-colors cursor-pointer group"
          >
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[path.severity] }} />
            <div className="flex-1">
              <div className="font-medium group-hover:text-[var(--neon-purple)] transition-colors">{path.name}</div>
              <div className="text-xs text-[var(--text-dim)] mt-1">
                {path.steps} steps • {path.assets} assets affected
              </div>
            </div>
            <button className="glow-btn px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <Eye size={12} /> Analyze
            </button>
          </motion.div>
        ))}
      </div>
    </div>
  </div>
);

// --- Response View ---
const ResponseView = () => {
  const [activeIncident, setActiveIncident] = useState(null);

  const incidents = [
    { id: 1, name: 'S3 Data Breach Response', status: 'active', severity: 'critical', actions: 5 },
    { id: 2, name: 'IAM Compromise Playbook', status: 'ready', severity: 'high', actions: 8 },
    { id: 3, name: 'Container Escape Protocol', status: 'ready', severity: 'critical', actions: 6 },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Playbooks */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
            <Target size={18} className="text-[var(--neon-orange)]" />
            Response Playbooks
          </h3>
          <div className="space-y-3">
            {incidents.map((incident) => (
              <div
                key={incident.id}
                onClick={() => setActiveIncident(incident.id === activeIncident ? null : incident.id)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${activeIncident === incident.id
                  ? 'border-[var(--neon-purple)] bg-[rgba(139,92,246,0.1)]'
                  : 'border-[rgba(255,255,255,0.05)] hover:border-[rgba(255,255,255,0.1)]'
                  }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[incident.severity] }} />
                    <span className="font-medium">{incident.name}</span>
                  </div>
                  <ChevronDown size={16} className={`text-[var(--text-secondary)] transition-transform ${activeIncident === incident.id ? 'rotate-180' : ''}`} />
                </div>
                <AnimatePresence>
                  {activeIncident === incident.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="mt-4 pt-4 border-t border-[rgba(255,255,255,0.05)]"
                    >
                      <p className="text-sm text-[var(--text-secondary)] mb-4">{incident.actions} automated actions ready to execute</p>
                      <button className="glow-btn px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2">
                        <Play size={14} /> Execute Playbook
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
            <Crosshair size={18} className="text-[var(--neon-green)]" />
            Quick Actions
          </h3>
          <div className="grid grid-cols-2 gap-4">
            {[
              { icon: Shield, label: 'Isolate Resource', color: '#ef4444' },
              { icon: RotateCcw, label: 'Rollback Changes', color: '#f59e0b' },
              { icon: Lock, label: 'Revoke Access', color: '#8b5cf6' },
              { icon: RefreshCw, label: 'Force Rotation', color: '#06b6d4' },
            ].map((action, idx) => (
              <button
                key={idx}
                className="flex flex-col items-center gap-3 p-4 rounded-xl bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.05)] hover:border-[var(--neon-purple)] transition-all group"
              >
                <action.icon size={24} style={{ color: action.color }} className="group-hover:scale-110 transition-transform" />
                <span className="text-sm text-[var(--text-secondary)] group-hover:text-white transition-colors">{action.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// --- Logs View ---
const LogsView = () => {
  const [logFilter, setLogFilter] = useState('all');

  const filteredLogs = logFilter === 'all'
    ? logsData
    : logsData.filter(l => l.type === logFilter);

  const getLogIcon = (type) => {
    switch (type) {
      case 'alert': return <AlertTriangle size={14} className="text-[#ef4444]" />;
      case 'warning': return <AlertCircle size={14} className="text-[#f59e0b]" />;
      case 'success': return <CheckCircle size={14} className="text-[var(--neon-green)]" />;
      default: return <FileText size={14} className="text-[var(--neon-blue)]" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex gap-3">
        {['all', 'alert', 'warning', 'success', 'info'].map((type) => (
          <button
            key={type}
            onClick={() => setLogFilter(type)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${logFilter === type
              ? 'bg-[var(--neon-purple)] text-white'
              : 'bg-[rgba(255,255,255,0.05)] text-[var(--text-secondary)] hover:text-white'
              }`}
          >
            {type.charAt(0).toUpperCase() + type.slice(1)}
          </button>
        ))}
      </div>

      <div className="glass-card p-0 font-mono text-sm overflow-hidden">
        <div className="p-4 border-b border-[rgba(255,255,255,0.05)] bg-[rgba(255,255,255,0.02)] flex items-center justify-between">
          <span className="text-[var(--text-secondary)]">Security Event Logs</span>
          <span className="text-xs text-[var(--neon-green)]">● Live</span>
        </div>
        <div className="divide-y divide-[rgba(255,255,255,0.02)]">
          {filteredLogs.map((log, idx) => (
            <motion.div
              key={log.id}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: idx * 0.05 }}
              className="flex items-start gap-4 p-4 hover:bg-[rgba(255,255,255,0.02)] transition-colors"
            >
              <span className="text-[var(--text-dim)] text-xs w-20 shrink-0">{log.timestamp}</span>
              {getLogIcon(log.type)}
              <span className="text-[var(--text-dim)] text-xs w-24 shrink-0">[{log.source}]</span>
              <span className="text-white">{log.message}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
};

// --- Dashboard View ---
const DashboardView = ({ mockData, findings, onFix, fixingId, onViewAll }) => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        title="Security Score"
        value={`${mockData.score}/100`}
        icon={Shield}
        color="var(--neon-purple)"
        delay={0.1}
      />
      <StatCard
        title="Active Threats"
        value={findings.filter(f => !f.fixed && (f.severity === 'critical' || f.severity === 'high')).length}
        subtext={`${findings.filter(f => !f.fixed && f.severity === 'critical').length} Critical, ${findings.filter(f => !f.fixed && f.severity === 'high').length} High`}
        icon={AlertTriangle}
        color="var(--neon-pink)"
        delay={0.2}
      />
      <StatCard
        title="Resources Scanned"
        value={mockData.scanned}
        subtext="+124 since yesterday"
        icon={Cloud}
        color="var(--neon-blue)"
        delay={0.3}
      />
      <StatCard
        title="Remediation Rate"
        value={`${Math.round((findings.filter(f => f.fixed).length / findings.length) * 100)}%`}
        subtext={`Auto-fixed ${findings.filter(f => f.fixed).length} issues`}
        icon={Zap}
        color="var(--neon-green)"
        delay={0.4}
      />
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-96">
      {/* Risk Trend Chart */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.5 }}
        className="glass-card col-span-2 p-6"
      >
        <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
          <Activity size={18} className="text-[var(--neon-purple)]" />
          Risk Velocity
        </h3>
        <div className="h-full pb-8">
          <ResponsiveContainer width="100%" height="85%">
            <AreaChart data={mockData.history}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--neon-purple)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--neon-purple)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="day" axisLine={false} tickLine={false} stroke="var(--text-secondary)" fontSize={12} />
              <YAxis axisLine={false} tickLine={false} stroke="var(--text-secondary)" fontSize={12} />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--glass-border)', borderRadius: '12px' }}
                itemStyle={{ color: '#fff' }}
              />
              <Area
                type="monotone"
                dataKey="score"
                stroke="var(--neon-purple)"
                strokeWidth={3}
                fillOpacity={1}
                fill="url(#colorScore)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      {/* Categories Radar */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.6 }}
        className="glass-card p-6 flex flex-col items-center justify-center relative"
      >
        <h3 className="text-lg font-semibold mb-2 w-full text-left flex items-center gap-2">
          <Server size={18} className="text-[var(--neon-blue)]" />
          Coverage
        </h3>
        <div className="w-full h-full">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={mockData.categories}>
              <PolarGrid stroke="rgba(255,255,255,0.1)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} />
              <Radar
                name="Score"
                dataKey="A"
                stroke="var(--neon-blue)"
                strokeWidth={2}
                fill="var(--neon-blue)"
                fillOpacity={0.2}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-24 h-24 bg-[var(--neon-blue)] opacity-5 blur-3xl rounded-full pointer-events-none"></div>
      </motion.div>
    </div>

    {/* Recent Findings Table */}
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.7 }}
      className="glass-card p-6"
    >
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <AlertTriangle size={18} className="text-[var(--neon-pink)]" />
          Critical Findings
        </h3>
        <button
          onClick={onViewAll}
          className="text-xs text-[var(--neon-purple)] hover:text-white transition-colors flex items-center gap-1"
        >
          View All <ArrowRight size={12} />
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-[var(--text-secondary)] uppercase bg-[rgba(255,255,255,0.02)] rounded-lg">
            <tr>
              <th className="px-4 py-3 rounded-l-lg">Severity</th>
              <th className="px-4 py-3">Finding</th>
              <th className="px-4 py-3">Resource</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3 rounded-r-lg">Action</th>
            </tr>
          </thead>
          <tbody>
            {findings.filter(f => !f.fixed).slice(0, 5).map((item) => (
              <tr key={item.id} className="border-b border-[rgba(255,255,255,0.02)] hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                <td className="px-4 py-4">
                  <SeverityPill severity={item.severity} />
                </td>
                <td className="px-4 py-3 font-medium">{item.title}</td>
                <td className="px-4 py-3 text-[var(--text-secondary)] font-mono text-xs">{item.resource}</td>
                <td className="px-4 py-3 text-[var(--text-dim)]">{item.type}</td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => onFix(item.id)}
                    disabled={fixingId === item.id}
                    className="glow-btn px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 disabled:opacity-50"
                  >
                    {fixingId === item.id ? (
                      <><RefreshCw size={12} className="animate-spin" /> Fixing...</>
                    ) : (
                      <><Zap size={12} /> Auto-Fix</>
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  </div>
);

// --- Main App ---
const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(true);
  const [mockData, setMockData] = useState(initialMockData);
  const [findings, setFindings] = useState(initialFindings);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [fixingId, setFixingId] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [showSearch, setShowSearch] = useState(false);
  const [findingsFilter, setFindingsFilter] = useState('all');
  const [useApi, setUseApi] = useState(false);
  const [apiConnected, setApiConnected] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Check API connection on toggle
  useEffect(() => {
    if (useApi) {
      api.health()
        .then(() => setApiConnected(true))
        .catch(() => {
          setApiConnected(false);
          setUseApi(false);
        });
    } else {
      setApiConnected(false);
    }
  }, [useApi]);

  useEffect(() => {
    setTimeout(() => setLoading(false), 1500);
  }, []);

  const addNotification = useCallback((message, type = 'success') => {
    const id = Date.now();
    setNotifications(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 4000);
  }, []);

  const dismissNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const handleRunScan = useCallback(async () => {
    if (scanning) return;

    setScanning(true);
    setScanProgress(0);

    if (useApi && apiConnected) {
      // Real API scan
      try {
        addNotification('Starting real cloud scan via API...', 'info');

        const { scan_id } = await api.createScan(['aws', 'azure', 'kubernetes'], true);
        addNotification(`Scan started: ${scan_id}`, 'info');

        // Poll for completion
        const result = await api.pollScanUntilComplete(scan_id, (progress) => {
          setScanProgress(Math.round(progress));
        });

        // Update dashboard with real results
        const results = result.results;
        setMockData(prev => ({
          ...prev,
          scanned: results.resources_scanned,
          score: 100 - results.overall_risk_score,
          history: [...prev.history.slice(1), { day: 'Now', score: 100 - results.overall_risk_score }]
        }));

        // Update findings from real scan
        if (results.misconfigurations?.misconfigurations) {
          const realFindings = results.misconfigurations.misconfigurations.map((m, idx) => ({
            id: idx + 100,
            title: m.title || m.rule_id,
            resource: m.resource_id || 'unknown',
            severity: m.severity?.toLowerCase() || 'medium',
            type: m.category || 'General',
            fixed: false,
            timestamp: 'Just now'
          }));
          setFindings(prev => [...realFindings, ...prev]);
        }

        addNotification(`Scan complete! Scanned ${results.resources_scanned} resources. Grade: ${results.overall_grade}`, 'success');
      } catch (err) {
        addNotification(`Scan failed: ${err.message}`, 'error');
      } finally {
        setScanning(false);
        setScanProgress(0);
      }
    } else {
      // Demo mode scan
      addNotification('Starting demo scan...', 'info');

      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            return 100;
          }
          return prev + 10;
        });
      }, 200);

      setTimeout(() => {
        setScanning(false);
        setScanProgress(0);

        const newResources = Math.floor(Math.random() * 50) + 10;
        const scoreIncrease = Math.floor(Math.random() * 5);

        setMockData(prev => ({
          ...prev,
          scanned: prev.scanned + newResources,
          score: Math.min(100, prev.score + scoreIncrease),
          history: [...prev.history.slice(1), { day: 'Now', score: Math.min(100, prev.score + scoreIncrease) }]
        }));

        addNotification(`Scan complete! Found ${newResources} new resources. Score improved by ${scoreIncrease} points.`, 'success');
      }, 2500);
    }
  }, [scanning, addNotification, useApi, apiConnected]);

  const handleAutoFix = useCallback((id) => {
    setFixingId(id);

    setTimeout(() => {
      setFindings(prev => prev.map(f =>
        f.id === id ? { ...f, fixed: true } : f
      ));
      setFixingId(null);

      const finding = findings.find(f => f.id === id);
      addNotification(`Fixed: ${finding?.title}`, 'success');

      setMockData(prev => ({
        ...prev,
        score: Math.min(100, prev.score + 2)
      }));
    }, 1500);
  }, [findings, addNotification]);

  const handleViewAll = useCallback(() => {
    setActiveTab('findings');
  }, []);

  if (loading) {
    return (
      <div className="h-screen w-full flex flex-col items-center justify-center bg-[var(--bg-deep)]">
        <div className="relative w-24 h-24">
          <div className="absolute inset-0 border-t-4 border-[var(--neon-purple)] rounded-full animate-spin"></div>
          <div className="absolute inset-2 border-r-4 border-[var(--neon-blue)] rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '0.8s' }}></div>
          <div className="absolute inset-4 border-b-4 border-[var(--neon-pink)] rounded-full animate-spin"></div>
        </div>
        <h1 className="mt-8 text-2xl font-bold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-[var(--neon-purple)] to-[var(--neon-blue)] uppercase">
          CloudSentinel
        </h1>
        <p className="text-[var(--text-dim)] text-sm mt-2 font-mono">Initializing Neural Defense Grid...</p>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-full text-[var(--text-primary)] font-sans selection:bg-[var(--neon-purple)] selection:text-white">
      {/* Toast Notifications */}
      <Toast notifications={notifications} onDismiss={dismissNotification} />

      {/* Search Modal */}
      <AnimatePresence>
        {showSearch && (
          <SearchModal
            isOpen={showSearch}
            onClose={() => setShowSearch(false)}
            onNavigate={setActiveTab}
            findings={findings}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        initial={{ x: -100, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.5 }}
        className="w-72 bg-[var(--bg-surface)] border-r border-[var(--glass-border)] flex flex-col p-6 z-20"
      >
        <div className="flex items-center gap-3 mb-12">
          <div className="relative">
            <div className="w-10 h-10 bg-[var(--neon-purple)] rounded-xl flex items-center justify-center shadow-[0_0_20px_rgba(139,92,246,0.5)]">
              <Shield color="white" size={24} />
            </div>
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-[var(--neon-green)] rounded-full border-2 border-[var(--bg-surface)] animate-pulse"></div>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">CloudSentinel</h1>
            <p className="text-[10px] text-[var(--text-dim)] uppercase tracking-widest">Enterprise Security</p>
          </div>
        </div>

        <nav className="flex-1 space-y-2">
          <SidebarItem icon={Activity} label="Dashboard" active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} />
          <SidebarItem icon={AlertTriangle} label="Findings" active={activeTab === 'findings'} onClick={() => setActiveTab('findings')} />
          <SidebarItem icon={Network} label="Attack Paths" active={activeTab === 'attacks'} onClick={() => setActiveTab('attacks')} />
          <SidebarItem icon={Target} label="Response" active={activeTab === 'response'} onClick={() => setActiveTab('response')} />
          <SidebarItem icon={Terminal} label="Logs" active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} />
        </nav>

        <div className="mt-auto space-y-4 pt-6 border-t border-[rgba(255,255,255,0.05)]">
          {/* API Connection Settings */}
          <div className="p-3 rounded-xl bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.05)]">
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="w-full flex items-center justify-between text-sm font-medium text-[var(--text-secondary)] hover:text-white transition-colors"
            >
              <span className="flex items-center gap-2">
                <Settings size={16} />
                API Connection
              </span>
              <ChevronDown size={14} className={`transition-transform ${showSettings ? 'rotate-180' : ''}`} />
            </button>

            <AnimatePresence>
              {showSettings && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="mt-3 pt-3 border-t border-[rgba(255,255,255,0.05)] space-y-3"
                >
                  {/* Toggle */}
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[var(--text-secondary)]">Use Backend API</span>
                    <button
                      onClick={() => setUseApi(!useApi)}
                      className={`w-10 h-5 rounded-full relative transition-colors ${useApi ? 'bg-[var(--neon-green)]' : 'bg-[rgba(255,255,255,0.1)]'}`}
                    >
                      <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${useApi ? 'left-5' : 'left-0.5'}`} />
                    </button>
                  </div>

                  {/* Status */}
                  <div className="flex items-center gap-2 text-xs">
                    {apiConnected ? (
                      <>
                        <Wifi size={12} className="text-[var(--neon-green)]" />
                        <span className="text-[var(--neon-green)]">Connected to backend</span>
                      </>
                    ) : (
                      <>
                        <WifiOff size={12} className="text-[var(--text-dim)]" />
                        <span className="text-[var(--text-dim)]">{useApi ? 'Connecting...' : 'Demo Mode'}</span>
                      </>
                    )}
                  </div>

                  {/* Instructions */}
                  {!apiConnected && useApi && (
                    <div className="text-xs text-[#f59e0b] bg-[rgba(245,158,11,0.1)] p-2 rounded-lg">
                      Start API: <code className="font-mono">python -m uvicorn src.api.routes:app --port 8000</code>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* User Profile */}
          <div className="flex items-center gap-3 p-3 rounded-xl bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.05)]">
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[var(--neon-blue)] to-[var(--neon-purple)]"></div>
            <div className="flex-1">
              <p className="text-sm font-medium">SecOps Team</p>
              <p className="text-xs text-[var(--text-dim)]">Admin Access</p>
            </div>
          </div>
        </div>
      </motion.aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        {/* Dynamic Background Elements */}
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[var(--neon-purple)] opacity-[0.03] blur-[150px] pointer-events-none rounded-full translate-x-1/2 -translate-y-1/2"></div>
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-[var(--neon-blue)] opacity-[0.03] blur-[150px] pointer-events-none rounded-full -translate-x-1/2 translate-y-1/2"></div>

        {/* Header */}
        <motion.header
          initial={{ y: -50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="h-20 flex items-center justify-between px-8 border-b border-[var(--glass-border)] bg-[rgba(5,5,16,0.8)] backdrop-blur-md z-10"
        >
          <div className="flex items-center gap-4 text-[var(--text-secondary)] text-sm">
            <span>Organization: <span className="text-white font-medium">Acme Corp</span></span>
            <span className="w-1 h-1 bg-[var(--text-dim)] rounded-full"></span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--neon-green)] animate-pulse"></span>
              System Operational
            </span>
            <span className="w-1 h-1 bg-[var(--text-dim)] rounded-full"></span>
            <span className={`flex items-center gap-2 px-2 py-0.5 rounded-full text-xs font-medium ${apiConnected ? 'bg-[rgba(16,185,129,0.15)] text-[var(--neon-green)]' : 'bg-[rgba(139,92,246,0.15)] text-[var(--neon-purple)]'}`}>
              {apiConnected ? <><Globe size={12} /> API Mode</> : <><Server size={12} /> Demo Mode</>}
            </span>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowSearch(true)}
              className="p-2 text-[var(--text-secondary)] hover:text-white transition-colors"
            >
              <Search size={20} />
            </button>
            <div className="h-6 w-px bg-[var(--glass-border)]"></div>
            <button
              onClick={handleRunScan}
              disabled={scanning}
              className="glow-btn px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 disabled:opacity-70"
            >
              {scanning ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  Scanning... {scanProgress}%
                </>
              ) : (
                <>
                  <Zap size={16} /> Run Scan
                </>
              )}
            </button>
          </div>
        </motion.header>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-8 relative z-0 scroll-smooth">
          <AnimatePresence mode="wait">
            {activeTab === 'dashboard' && (
              <motion.div
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="mb-8">
                  <h2 className="text-3xl font-bold tracking-tight mb-2">Security Overview</h2>
                  <p className="text-[var(--text-secondary)]">Real-time threat monitoring and risk assessment.</p>
                </div>
                <DashboardView
                  mockData={mockData}
                  findings={findings}
                  onFix={handleAutoFix}
                  fixingId={fixingId}
                  onViewAll={handleViewAll}
                />
              </motion.div>
            )}

            {activeTab === 'findings' && (
              <motion.div
                key="findings"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="mb-8">
                  <h2 className="text-3xl font-bold tracking-tight mb-2">Security Findings</h2>
                  <p className="text-[var(--text-secondary)]">All vulnerabilities and misconfigurations detected.</p>
                </div>
                <FindingsView
                  findings={findings}
                  onFix={handleAutoFix}
                  fixingId={fixingId}
                  filter={findingsFilter}
                  setFilter={setFindingsFilter}
                />
              </motion.div>
            )}

            {activeTab === 'attacks' && (
              <motion.div
                key="attacks"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="mb-8">
                  <h2 className="text-3xl font-bold tracking-tight mb-2">Attack Paths</h2>
                  <p className="text-[var(--text-secondary)]">Potential attack vectors and exploitation paths.</p>
                </div>
                <AttackPathsView />
              </motion.div>
            )}

            {activeTab === 'response' && (
              <motion.div
                key="response"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="mb-8">
                  <h2 className="text-3xl font-bold tracking-tight mb-2">Incident Response</h2>
                  <p className="text-[var(--text-secondary)]">Automated playbooks and response actions.</p>
                </div>
                <ResponseView />
              </motion.div>
            )}

            {activeTab === 'logs' && (
              <motion.div
                key="logs"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="mb-8">
                  <h2 className="text-3xl font-bold tracking-tight mb-2">Security Logs</h2>
                  <p className="text-[var(--text-secondary)]">Real-time security event monitoring.</p>
                </div>
                <LogsView />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
};

export default App;
