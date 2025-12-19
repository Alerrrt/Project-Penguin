import React from 'react';
import { Settings } from 'lucide-react';

interface HeaderProps {
    isScanning: boolean;
    denseMode: boolean;
    setDenseMode: (value: boolean | ((val: boolean) => boolean)) => void;
}

const Header: React.FC<HeaderProps> = ({ isScanning, denseMode, setDenseMode }) => {
    return (
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
                    onClick={() => setDenseMode((v) => !v)}
                >
                    {denseMode ? 'Dense: On' : 'Dense: Off'}
                </button>
            </div>
        </header>
    );
};

export default Header;
