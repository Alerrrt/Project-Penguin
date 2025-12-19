import React from 'react';
import { Shield, Zap, BarChart3, ArrowRight, Play, Settings, Clock } from 'lucide-react';

interface HeroLandingProps {
  onStartScan: () => void;
  onShowHistory: () => void;
  onShowConfig: () => void;
}

const HeroLanding: React.FC<HeroLandingProps> = ({ onStartScan, onShowHistory, onShowConfig }) => {
  const handleStartScan = () => {
    // This will trigger the config panel to open, where user can enter URL and start scan
    onStartScan();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-surface to-background flex flex-col">
      {/* Hero Section */}
      <div className="flex-1 flex flex-col items-center justify-center px-6 py-12 text-center">
        {/* Main Logo and Title */}
        <div className="mb-12">
          <div className="relative mb-8">
            <div className="absolute inset-0 bg-primary/20 rounded-full blur-3xl"></div>
            <div className="relative bg-gradient-to-r from-primary to-cyan-400 rounded-full p-6 w-24 h-24 mx-auto flex items-center justify-center">
              <Shield className="w-12 h-12 text-background" />
            </div>
          </div>
          <h1 className="text-5xl md:text-7xl font-bold text-text mb-6">
            Project Penguin
          </h1>
          <p className="text-xl md:text-2xl text-textSecondary max-w-3xl mx-auto leading-relaxed">
            Advanced Security Scanning & Vulnerability Assessment Platform
          </p>
        </div>

        {/* Main CTA */}
        <div className="mb-16">
          <button
            onClick={handleStartScan}
            className="group bg-gradient-to-r from-primary to-cyan-400 hover:from-cyan-400 hover:to-primary text-background font-bold py-6 px-12 rounded-2xl text-xl transition-all duration-300 transform hover:scale-105 hover:shadow-2xl hover:shadow-primary/25"
          >
            <div className="flex items-center space-x-3">
              <Play className="w-6 h-6 group-hover:animate-pulse" />
              <span>Start Security Scan</span>
              <ArrowRight className="w-6 h-6 group-hover:translate-x-1 transition-transform" />
            </div>
          </button>
        </div>

        {/* Feature Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto mb-16">
          <div className="bg-surface/50 backdrop-blur-sm rounded-2xl p-8 border border-border/50 hover:border-primary/50 transition-all duration-300 group">
            <div className="bg-primary/20 rounded-2xl p-4 w-16 h-16 mx-auto mb-6 flex items-center justify-center group-hover:scale-110 transition-transform">
              <Zap className="w-8 h-8 text-primary" />
            </div>
            <h3 className="text-xl font-bold text-text mb-4">Lightning Fast</h3>
            <p className="text-textSecondary leading-relaxed">
              Advanced scanning algorithms deliver comprehensive security assessments in minutes, not hours.
            </p>
          </div>

          <div className="bg-surface/50 backdrop-blur-sm rounded-2xl p-8 border border-border/50 hover:border-primary/50 transition-all duration-300 group">
            <div className="bg-primary/20 rounded-2xl p-4 w-16 h-16 mx-auto mb-6 flex items-center justify-center group-hover:scale-110 transition-transform">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <h3 className="text-xl font-bold text-text mb-4">Comprehensive Coverage</h3>
            <p className="text-textSecondary leading-relaxed">
              OWASP Top 10, CVE databases, and custom vulnerability patterns for complete security analysis.
            </p>
          </div>

          <div className="bg-surface/50 backdrop-blur-sm rounded-2xl p-8 border border-border/50 hover:border-primary/50 transition-all duration-300 group">
            <div className="bg-primary/20 rounded-2xl p-4 w-16 h-16 mx-auto mb-6 flex items-center justify-center group-hover:scale-110 transition-transform">
              <BarChart3 className="w-8 h-8 text-primary" />
            </div>
            <h3 className="text-xl font-bold text-text mb-4">Real-time Analytics</h3>
            <p className="text-textSecondary leading-relaxed">
              Live progress tracking, detailed reports, and actionable insights for security professionals.
            </p>
          </div>
        </div>

        {/* Secondary Actions */}
        <div className="flex flex-col sm:flex-row gap-4">
          <button
            onClick={onShowConfig}
            className="flex items-center justify-center space-x-2 bg-surface hover:bg-surface/80 text-text font-semibold py-4 px-8 rounded-xl border border-border hover:border-primary/50 transition-all duration-300"
          >
            <Settings className="w-5 h-5" />
            <span>Customize Scanners</span>
          </button>

          <button
            onClick={onShowHistory}
            className="flex items-center justify-center space-x-2 bg-surface hover:bg-surface/80 text-text font-semibold py-4 px-8 rounded-xl border border-border hover:border-primary/50 transition-all duration-300"
          >
            <Clock className="w-5 h-5" />
            <span>View History</span>
          </button>
        </div>
      </div>

      {/* Footer Section */}
      <div className="border-t border-border/50 bg-surface/30 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-6 py-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <h4 className="text-lg font-bold text-text mb-4">Platform</h4>
              <ul className="space-y-2 text-textSecondary">
                <li>Security Scanning</li>
                <li>Vulnerability Assessment</li>
                <li>Real-time Monitoring</li>
                <li>Comprehensive Reports</li>
              </ul>
            </div>

            <div>
              <h4 className="text-lg font-bold text-text mb-4">Scanners</h4>
              <ul className="space-y-2 text-textSecondary">
                <li>OWASP Top 10</li>
                <li>CVE Database</li>
                <li>Custom Patterns</li>
                <li>API Security</li>
              </ul>
            </div>

            <div>
              <h4 className="text-lg font-bold text-text mb-4">Reports</h4>
              <ul className="space-y-2 text-textSecondary">
                <li>PDF Export</li>
                <li>CSV Download</li>
                <li>Risk Assessment</li>
                <li>Remediation Guide</li>
              </ul>
            </div>

            <div>
              <h4 className="text-lg font-bold text-text mb-4">Support</h4>
              <ul className="space-y-2 text-textSecondary">
                <li>Documentation</li>
                <li>API Reference</li>
                <li>Community</li>
                <li>Contact</li>
              </ul>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-border/50 text-center text-textSecondary">
            <p>&copy; 2024 Project Penguin Security Platform. Advanced vulnerability assessment for modern applications.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HeroLanding;
