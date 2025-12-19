import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Shield, Globe, Settings, Pause, Clock, ChevronsRight, FileText, Zap, Menu, X as CloseIcon, SlidersHorizontal, ChevronDown } from 'lucide-react';
import ScanHistory from './components/ScanHistory';
import { useScan } from './context/ScanContext';
import { defaultScanProgress, defaultScanStats } from './context/ScanContext';
import * as scanApi from './api/scanApi';
import { useToast } from './components/ToastProvider';
import ScannersList from './components/ScannersList';
import VulnerabilityList, { GroupedVulnerability } from './components/VulnerabilityList';
import VulnerabilityDetails from './components/VulnerabilityDetails';
import ScanProgress from './components/ScanProgress';
import LiveModuleStatus from './components/LiveModuleStatus';
import ScanReport from './components/ScanReport';
import ScanHistoryModal from './components/ScanHistoryModal';
import ScanConfigPanel from './components/ScanConfigPanel';
import TechnologyVulnerabilities from './components/TechnologyVulnerabilities';
import JavaScriptVulnerabilities from './components/JavaScriptVulnerabilities';
import ModuleStatusGrid from './components/ModuleStatusGrid';
import SecurityPostureChart from './components/SecurityPostureChart';
import './posture-summary.css';
import HeroLanding from './components/HeroLanding';
import SiteSnippetCard from './components/SiteSnippetCard';
import { checkBackendReady } from './api/scanApi';

// Helper for timeout
function timeoutPromise(ms: number) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms));
}

// PATCH: Default scanners to exclude long-running and off-by-default scanners
const longRunningScanners = [
  'automated_cve_lookup_scanner',
  'subdomain_dns_enumeration_scanner',
  'ssl_tls_configuration_audit_scanner',
  'api_fuzzing_scanner',
];
const offByDefaultScanners = [
  'sql_injection_scanner',
  'broken_access_control_scanner',
  'broken_authentication_scanner',
  'open_redirect_scanner',
];

const App: React.FC = () => {
  const {
    isScanning,
    setIsScanning,
    scanProgress,
    scanStats,
    setScanStats,
    vulnerabilities,
    selectedVuln,
    setSelectedVuln,
    filterSeverity,
    setFilterSeverity,
    scanId,
    setScanId,
    loading,
    error,
    setVulnerabilities,
    modules,
    activityLogs,
    stopScan,
    setScanProgress,
  } = useScan();
  const { showToast } = useToast();
  const [targetInput, setTargetInput] = useState('');
  const [cancelLoading, setCancelLoading] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [isSidebarOpen, setSidebarOpen] = useState(false);
  const [showConfigPanel, setShowConfigPanel] = useState(false);
  const [customScanners, setCustomScanners] = useState<string[]>([]);
  const [isScannersOpen, setIsScannersOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [denseMode, setDenseMode] = useState(false);
  const prevIsScanning = useRef(false);
  const [scanTimedOut, setScanTimedOut] = useState(false);
  const [hasSubmittedUrl, setHasSubmittedUrl] = useState(false);
  const [scannerMetadata, setScannerMetadata] = useState<Record<string, {
    name: string;
    description: string;
    owasp_category: string;
    vulnerability_types: string[];
    scan_type: string;
    intensity: string;
    author: string;
    version: string;
  }>>({});
  const [backendReady, setBackendReady] = useState(false);
  const [readyChecked, setReadyChecked] = useState(false);

  useEffect(() => {
    if (prevIsScanning.current && !isScanning && scanId) {
      showToast('Scan completed!', 'success');
    }
    prevIsScanning.current = isScanning;
  }, [isScanning, scanId, showToast]);

  useEffect(() => {
    // Fetch scanners list and set default customScanners
    async function fetchAndSetDefaultScanners() {
      try {
        const data = await scanApi.fetchScannersList();
        setScannerMetadata(data);
        const scannersArr = Object.entries(data).map(([key, meta]) => ({ key, ...(meta as any) }));
        setCustomScanners(
          scannersArr
            .filter(s => !longRunningScanners.includes(s.key) && !offByDefaultScanners.includes(s.key))
            .map(s => s.key)
        );
      } catch (err) {
        // fallback: do nothing
      }
    }
    fetchAndSetDefaultScanners();
  }, []);

  useEffect(() => {
    checkBackendReady().then(setBackendReady).finally(() => setReadyChecked(true));
  }, []);

  const handleScanToggle = async (scanType: 'full_scan' | 'quick_scan' | 'custom_scan' | 'stop' = 'full_scan') => {
    if (scanType === 'stop') {
      if (!scanId) return;
      setCancelLoading(true);
      try {
        await scanApi.stopScan(scanId);
        setIsScanning(false);
        setScanId(null);
        setHasSubmittedUrl(false);
        showToast('Scan cancelled.', 'success');
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to cancel scan.';
        showToast(message, 'error');
      } finally {
        setCancelLoading(false);
      }
      return;
    }
    
    if (!isScanning) {
      if (!targetInput.trim()) {
        showToast('Please enter a target URL.', 'error');
        return;
      }
      setScanTimedOut(false);
      try {
        const options = { scanners: customScanners };
        const scanPromise = scanApi.startScan({ target: targetInput, scan_type: scanType, options });
        const res = await Promise.race([
          scanPromise,
          timeoutPromise(300_000) // Increased to 5 minutes to allow for longer scans
        ]);
        console.log('App.tsx: Setting scan state - scanId:', res.scan_id, 'isScanning: true');
        setScanId(res.scan_id);
        setIsScanning(true);
        setHasSubmittedUrl(true);
        setScanProgress({
          ...(typeof scanProgress === 'object' && scanProgress !== null ? scanProgress : defaultScanProgress),
          currentUrl: targetInput,
          progress: 0,
          phase: 'Initializing...',
          eta: '...'
        });
        setScanStats({ ...(typeof scanStats === 'object' && scanStats !== null ? scanStats : defaultScanStats), target: targetInput });
        setVulnerabilities([]);
        setSelectedVuln(null);
        showToast(`Scan started (${scanType.replace('_', ' ')})`, 'success');
      } catch (err) {
        if (err instanceof Error && err.message === 'timeout') {
          setScanTimedOut(true);
          if (scanId) {
            try { await scanApi.stopScan(scanId); } catch {}
          }
          showToast('Scan timed out after 5 minutes. The scan may still be running in the background.', 'error');
        } else {
          const message = err instanceof Error ? err.message : 'Failed to start scan.';
          showToast(message, 'error');
        }
      }
    }
  };

  // Note: cancel handled via stopScan from context; dedicated handler removed to avoid duplication.

  const handleViewReportFromHistory = async (historicalScanId: string) => {
    try {
      // Here you would fetch the full scan data for the historicalScanId
      // For now, let's assume we can get the necessary data.
      // This is a placeholder for fetching and setting state for an old report.
      console.log(`Fetching report for scan ID: ${historicalScanId}`);
      // As a placeholder, we could fetch the status and if it has results, show them.
      // The current API doesn't support fetching a full past report object easily,
      // so we will just log it and close the history modal for now.
      showToast(`Loading report for scan ${historicalScanId}...`, 'success');
      // In a real implementation, you'd fetch the data, set it to state,
      // and then open the ScanReport component.
      // e.g. const reportData = await scanApi.fetchScanReport(historicalScanId);
      //      setHistoricalReportData(reportData);
      //      setShowReport(true);
      setShowHistoryModal(false);
    } catch (error) {
      showToast('Could not load historical report.', 'error');
    }
  };

  const handleSaveScanConfig = (selectedScanners: string[]) => {
    setCustomScanners(selectedScanners);
    showToast(`Configuration saved with ${selectedScanners.length} scanners.`, 'success');
    handleScanToggle('custom_scan');
  };

  // Grouped vulnerabilities for results view are computed in groupedGeneralVulnerabilities below

  const technologyVulnerabilities = useMemo(() => {
    if (!vulnerabilities) return [];
    return vulnerabilities.filter(vuln => vuln.category === 'technology-fingerprint');
  }, [vulnerabilities]);

  const javaScriptVulnerabilities = useMemo(() => {
    if (!vulnerabilities) return [];
    return vulnerabilities.filter(vuln => vuln.category === 'vulnerable-js-library');
  }, [vulnerabilities]);

  const generalVulnerabilities = useMemo(() => {
    if (!vulnerabilities) return [];
    const specialCategories = ['technology-fingerprint', 'vulnerable-js-library'];
    return vulnerabilities.filter(vuln => !specialCategories.includes(vuln.category));
  }, [vulnerabilities]);

  const groupedGeneralVulnerabilities = useMemo(() => {
    const groups: Record<string, GroupedVulnerability> = {};
    generalVulnerabilities.forEach(vuln => {
      const groupKey = `${vuln.title}-${vuln.cwe}`;
      if (!groups[groupKey]) {
        groups[groupKey] = {
          groupKey,
          title: vuln.title,
          severity: vuln.severity,
          cwe: vuln.cwe,
          cve: vuln.cve,
          description: vuln.description,
          remediation: vuln.remediation,
          confidence: vuln.confidence,
          cvss: vuln.cvss,
          instances: [],
          count: 0,
        };
      }
      groups[groupKey].instances.push(vuln);
      groups[groupKey].count++;
    });
    return Object.values(groups).sort((a, b) => b.cvss - a.cvss);
  }, [generalVulnerabilities]);

  if (!readyChecked) {
    return <div>Loading backend...</div>;
  }
  if (!backendReady) {
    return <div>Backend not ready. Please try again later.</div>;
  }

  return (
    <div className="min-h-screen bg-background text-text font-sans">
      <div className="flex relative md:static">
        {/* Mobile menu button */}
        <button
          className="md:hidden absolute top-4 left-4 z-20 p-2 text-text"
          onClick={() => setSidebarOpen(!isSidebarOpen)}
        >
          {isSidebarOpen ? <CloseIcon /> : <Menu />}
        </button>

        {/* Sidebar */}
        <aside className={`absolute md:relative z-10 w-80 bg-surface h-screen p-4 flex flex-col space-y-6 transform ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0 transition-transform duration-300 ease-in-out`}>
          <div className="flex items-center space-x-3 px-2">
            <Shield className="h-8 w-8 text-primary" />
            <h1 className="text-2xl font-bold text-text">Project Penguin</h1>
          </div>
          
          <section className="bg-background rounded-lg p-4">
            <div className="flex items-center mb-4">
              <Globe className="h-5 w-5 text-primary mr-3" />
              <h2 className="text-lg font-semibold">Target</h2>
            </div>
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="http://example.com"
                  className="w-full bg-background text-text rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
                  disabled={isScanning}
                />
              </div>
              {!isScanning ? (
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleScanToggle('full_scan')}
                    disabled={loading || cancelLoading}
                    className="w-full flex items-center justify-center bg-primary hover:bg-opacity-80 text-background font-bold py-2.5 px-4 rounded-md transition-all disabled:opacity-50"
                  >
                    <ChevronsRight className="h-5 w-5 mr-2" />
                    Start Scan
                  </button>
                  <button
                    onClick={() => handleScanToggle('quick_scan')}
                    disabled={loading || cancelLoading || isScanning}
                    title="Quick Scan: Runs a subset of fast, non-intrusive scanners."
                    className="flex items-center justify-center bg-secondary hover:bg-opacity-80 text-background font-bold p-2.5 rounded-md transition-all disabled:opacity-50"
                  >
                    <Zap className="h-5 w-5" />
                  </button>
                  <button
                    onClick={() => setShowConfigPanel(true)}
                    disabled={loading || cancelLoading || isScanning}
                    title="Custom Scan: Select which scanners to run."
                    className="flex items-center justify-center bg-surface hover:bg-opacity-80 text-text font-bold p-2.5 rounded-md transition-all disabled:opacity-50"
                  >
                    <SlidersHorizontal className="h-5 w-5" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={stopScan}
                  className="w-full flex items-center justify-center bg-error hover:bg-opacity-80 text-background font-bold py-2.5 px-4 rounded-md transition-all disabled:opacity-50"
                >
                  <Pause className="h-5 w-5 mr-2" />
                  Stop Scan
                </button>
              )}
            </div>
          </section>

          {/* Progressive UI Reveal - Only show these sections after scan starts */}
          {hasSubmittedUrl && (
            <>
            <section className="bg-background rounded-lg p-4 flex-grow flex flex-col">
              <div 
                className="flex items-center justify-between mb-4 cursor-pointer group"
                onClick={() => setIsScannersOpen(!isScannersOpen)}
              >
                <div className="flex items-center">
                  <Settings className="h-5 w-5 text-primary mr-3 group-hover:text-cyan-300 transition-colors" />
                  <h2 className="text-lg font-semibold group-hover:text-gray-100 transition-colors">Available Scanners</h2>
                </div>
                <ChevronDown className={`h-5 w-5 text-textSecondary transform transition-transform ${isScannersOpen ? 'rotate-180' : ''}`} />
              </div>
              {isScannersOpen && <ScannersList onStartCustomScan={handleSaveScanConfig} />}
            </section>

            <section className="bg-background rounded-lg p-4">
              <div 
                className="flex items-center justify-between mb-4 cursor-pointer group"
                onClick={() => setIsHistoryOpen(!isHistoryOpen)}
              >
                <div className="flex items-center">
                  <Clock className="h-5 w-5 text-primary mr-3 group-hover:text-cyan-300 transition-colors" />
                  <h2 className="text-lg font-semibold group-hover:text-gray-100 transition-colors">Scan History</h2>
                </div>
                <ChevronDown className={`h-5 w-5 text-textSecondary transform transition-transform ${isHistoryOpen ? 'rotate-180' : ''}`} />
              </div>
              {isHistoryOpen && <ScanHistory onViewAll={() => setShowHistoryModal(true)} onSelectScan={handleViewReportFromHistory} />}
            </section>
            </>
          )}
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 h-screen overflow-y-auto w-full">
          <header className="flex justify-between items-center mb-6">
            <div className="hidden md:flex items-center space-x-3">
              <div className="flex items-center space-x-2 text-sm">
                <span className={`h-2.5 w-2.5 rounded-full ${isScanning ? 'bg-warning animate-pulse' : 'bg-success'}`} />
                <span className="text-textSecondary">{isScanning ? 'Scan in Progress' : 'System Online'}</span>
              </div>
              <button title="Settings" className="p-2 rounded-md bg-surface hover:bg-opacity-80 focus-ring">
                <Settings className="h-5 w-5" />
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 text-xs rounded-full border border-border/60 bg-surface/60 text-textSecondary">Project Penguin</span>
              <button
                className={`px-3 py-1 text-xs rounded-md border ${denseMode ? 'bg-primary text-background border-primary' : 'bg-surface text-text border-border'} focus-ring`}
                title="Toggle dense mode"
                onClick={() => setDenseMode(v => !v)}
              >
                {denseMode ? 'Dense: On' : 'Dense: Off'}
              </button>
            </div>
          </header>

          {error && (
              <div className="bg-error/20 border border-error text-text px-4 py-3 rounded-md mb-4 text-sm">
                  {error}
              </div>
          )}
          
          {scanTimedOut && (
            <div className="bg-error/20 border border-error text-text px-4 py-3 rounded-md mb-4 text-sm">
              Scan timed out after 120 seconds. Please try again or adjust your scanner selection.
            </div>
          )}
          
          {/* Progressive UI Reveal - Show scanning interface first */}
          {isScanning && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6 items-stretch">
                <div className="h-full bg-surface/70 border border-border rounded-xl p-1">
                  <ScanProgress scanProgress={scanProgress} isScanning={isScanning} dense={denseMode} />
                </div>
                <div className="h-full">
                  <SiteSnippetCard targetUrl={scanProgress?.currentUrl || targetInput} />
                </div>
              </div>
              <div className="bg-surface/70 border border-border rounded-xl p-4">
                <ModuleStatusGrid modules={modules} scannerMetadata={scannerMetadata} />
              </div>
              <div className="mt-6 grid grid-cols-1 gap-6">
                <SecurityPostureChart
                  vulnerabilities={vulnerabilities}
                  loading={isScanning && vulnerabilities.length === 0}
                />
                <div className="bg-surface/70 border border-border rounded-xl p-4">
                  <LiveModuleStatus activityLogs={activityLogs} />
                </div>
              </div>
            </>
          )}
          
          {/* Progressive UI Reveal - Show results only after scan completion */}
          {!hasSubmittedUrl ? (
            <HeroLanding 
              onStartScan={() => {
                // Show the config panel to start scan
                setShowConfigPanel(true);
              }}
              onShowHistory={() => setShowHistoryModal(true)}
              onShowConfig={() => setShowConfigPanel(true)}
            />
          ) : (
            <>
              {!isScanning && vulnerabilities.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-center text-textSecondary">
                  <Shield className="h-16 w-16 text-primary mb-4 opacity-50" />
                  <p className="text-lg">No vulnerabilities found or no scan performed yet.</p>
                  <p>Enter a target URL and start a scan to see the results.</p>
                </div>
              )}

              {!isScanning && vulnerabilities.length > 0 && (
                <>
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-2xl font-bold">Scan Results</h2>
                    <button
                      onClick={() => setShowReport(true)}
                      className="flex items-center bg-primary hover:bg-opacity-80 text-background font-bold py-2 px-4 rounded-md transition-all"
                    >
                      <FileText size={18} className="mr-2" />
                      View Report
                    </button>
                  </div>
                  {technologyVulnerabilities.length > 0 && (
                    <div className="mb-6">
                      <TechnologyVulnerabilities vulnerabilities={technologyVulnerabilities} />
                    </div>
                  )}
                  {javaScriptVulnerabilities.length > 0 && (
                    <div className="mb-6">
                      <JavaScriptVulnerabilities vulnerabilities={javaScriptVulnerabilities} />
                    </div>
                  )}
                  <div className="grid grid-cols-3 gap-6">
                    <div className="col-span-1">
                      <VulnerabilityList
                        groupedVulnerabilities={groupedGeneralVulnerabilities}
                        selectedVuln={selectedVuln}
                        onSelectVuln={setSelectedVuln}
                        filterSeverity={filterSeverity}
                        setFilterSeverity={setFilterSeverity}
                      />
                    </div>
                    <div className="col-span-2">
                      {selectedVuln ? (
                        <VulnerabilityDetails vulnerability={selectedVuln} onClose={() => setSelectedVuln(null)} />
                      ) : (
                        <div className="bg-surface rounded-lg p-6 flex items-center justify-center h-full">
                          <div className="text-center text-textSecondary">
                            <p>Select a vulnerability to see details.</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  {!isScanning && vulnerabilities.length > 0 && (
                    <div className="mt-8 mb-8">
                      <h2 className="text-xl font-bold mb-4 text-primary">Overall Security Posture</h2>
                      <div className="flex gap-4 flex-wrap">
                        <div className="posture-item critical">Critical: <span>{vulnerabilities.filter(v => v.severity === 'Critical').length}</span></div>
                        <div className="posture-item high">High: <span>{vulnerabilities.filter(v => v.severity === 'High').length}</span></div>
                        <div className="posture-item medium">Medium: <span>{vulnerabilities.filter(v => v.severity === 'Medium').length}</span></div>
                        <div className="posture-item low">Low: <span>{vulnerabilities.filter(v => v.severity === 'Low').length}</span></div>
                        <div className="posture-item info">Info: <span>{vulnerabilities.filter(v => v.severity === 'Info').length}</span></div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </main>
      </div>
      {showReport && (
        <ScanReport
          scanStats={scanStats}
          groupedVulnerabilities={groupedGeneralVulnerabilities}
          allVulnerabilities={vulnerabilities}
          scanId={scanId || undefined}
          onClose={() => setShowReport(false)}
        />
      )}
      {showHistoryModal && (
        <ScanHistoryModal
          onClose={() => setShowHistoryModal(false)}
          onViewReport={handleViewReportFromHistory}
        />
      )}
      <ScanConfigPanel
        isOpen={showConfigPanel}
        onClose={() => setShowConfigPanel(false)}
        onSave={handleSaveScanConfig}
        onStartScan={(url, scanners) => {
          setTargetInput(url);
          setCustomScanners(scanners);
          handleScanToggle('custom_scan');
        }}
        initialSelectedScanners={customScanners}
      />
    </div>
  );
};

export default App;