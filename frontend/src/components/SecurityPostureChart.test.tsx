// Vitest test file for SecurityPostureChart
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SecurityPostureChart from './SecurityPostureChart';
import { VulnerabilityData } from './VulnerabilityList';

describe('SecurityPostureChart', () => {
  const sampleVulnerabilities: VulnerabilityData[] = [
    { id: '1', title: 'Vuln 1', severity: 'High', description: 'Desc 1', cwe: 'CWE-1', cve: 'CVE-1', cvss: 8.0, remediation: 'Fix it', location: 'loc1', confidence: 1, category: 'cat1', impact: 'imp1' },
    { id: '2', title: 'Vuln 2', severity: 'Medium', description: 'Desc 2', cwe: 'CWE-2', cve: 'CVE-2', cvss: 5.0, remediation: 'Fix it', location: 'loc2', confidence: 1, category: 'cat2', impact: 'imp2' },
  ];

  it('renders chart title and legend', () => {
    render(<SecurityPostureChart vulnerabilities={sampleVulnerabilities} />);
    expect(screen.getByText(/Overall Security Posture/i)).toBeInTheDocument();
    expect(screen.getByText(/Passed/i)).toBeInTheDocument();
    expect(screen.getByText(/Warnings/i)).toBeInTheDocument();
    expect(screen.getByText(/Failed/i)).toBeInTheDocument();
  });

  it('renders correct values in the chart', () => {
    render(<SecurityPostureChart vulnerabilities={sampleVulnerabilities} />);
    // Pie chart labels (e.g., Passed: 67%)
    expect(screen.getByText(/Passed: [0-9]+%/)).toBeInTheDocument();
    expect(screen.getByText(/Warnings: [0-9]+%/)).toBeInTheDocument();
    expect(screen.getByText(/Failed: [0-9]+%/)).toBeInTheDocument();
  });

  it('renders the PieChart SVG', () => {
    render(<SecurityPostureChart vulnerabilities={sampleVulnerabilities} />);
    expect(document.querySelector('svg')).toBeInTheDocument();
  });
}); 