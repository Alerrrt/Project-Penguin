import React, { useState } from 'react';
import { Shield, Globe, Settings, Pause, Zap, X as CloseIcon, SlidersHorizontal, ChevronDown, ChevronsRight, Clock } from 'lucide-react';
import ScannersList from '../ScannersList';
import ScanHistory from '../ScanHistory';

interface SidebarProps {
    isSidebarOpen: boolean;
    setSidebarOpen: (isOpen: boolean) => void;
    targetInput: string;
    setTargetInput: (value: string) => void;
    isScanning: boolean;
    loading: boolean;
    cancelLoading: boolean;
    handleScanToggle: (type?: 'full_scan' | 'quick_scan' | 'custom_scan' | 'stop') => void;
    stopScan: () => void;
    setShowConfigPanel: (show: boolean) => void;
    hasSubmittedUrl: boolean;
    onSaveScanConfig: (selected: string[]) => void;
    setShowHistoryModal: (show: boolean) => void;
    onViewReportFromHistory: (id: string) => void;
}

const Sidebar: React.FC<SidebarProps> = ({
    isSidebarOpen,
    setSidebarOpen,
    targetInput,
    setTargetInput,
    isScanning,
    loading,
    cancelLoading,
    handleScanToggle,
    stopScan,
    setShowConfigPanel,
    hasSubmittedUrl,
    onSaveScanConfig,
    setShowHistoryModal,
    onViewReportFromHistory
}) => {
    const [isScannersOpen, setIsScannersOpen] = useState(false);
    const [isHistoryOpen, setIsHistoryOpen] = useState(false);

    return (
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
                        {isScannersOpen && <ScannersList onStartCustomScan={onSaveScanConfig} />}
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
                        {isHistoryOpen && <ScanHistory onViewAll={() => setShowHistoryModal(true)} onSelectScan={onViewReportFromHistory} />}
                    </section>
                </>
            )}
        </aside>
    );
};

export default Sidebar;
