import React, { useRef, useState } from 'react';
import { GroupedVulnerability, VulnerabilityData } from './VulnerabilityList';
import { ScanStats } from './StatsCards';
import { X, Download } from 'lucide-react';

interface ScanReportProps {
  scanStats: ScanStats;
  groupedVulnerabilities: GroupedVulnerability[];
  allVulnerabilities: VulnerabilityData[]; // For technology stack
  scanId?: string; // Add scan ID for PDF generation
  onClose: () => void;
}

interface TechnologyFinding {
  technology?: string;
  cve?: string;
  title: string;
  description: string;
  references?: string[];
  severity?: string;
  category?: string;
}

const ScanReport: React.FC<ScanReportProps> = ({ scanStats, groupedVulnerabilities, allVulnerabilities, scanId, onClose }) => {
  const reportContentRef = useRef<HTMLDivElement>(null);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({ email: '' });
  const [formError, setFormError] = useState('');

  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleDownloadPdf = () => {
    // Instead of generating PDF immediately, show the form
    setShowForm(true);
  };

  const handleFormChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    if (!formData.email) {
      setFormError('Please enter your business email.');
      return;
    }
    setIsSubmitting(true);
    try {
      // Call backend to save user info
      const res = await fetch('/api/reports/scans/user_info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: formData.email, url: scanStats.target })
      });
      if (!res.ok) throw new Error('Failed to save user info');

      // Call backend to generate and download PDF
      const pdfRes = await fetch('/api/reports/scans/generate_pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: scanStats.target,
          scan_id: scanId || 'unknown' // Include scan ID for dynamic PDF generation
        })
      });
      if (!pdfRes.ok) throw new Error('Failed to generate PDF');
      const blob = await pdfRes.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'project_echo_security_report.pdf';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setShowForm(false);
    } catch (err) {
      setFormError('Failed to submit or download PDF. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDownloadCsv = () => {
    const headers = [
      "Title", "Severity", "CVSS", "CWE", "Count", "Description", "Remediation", "Affected Locations"
    ];

    const rows = groupedVulnerabilities.map(vuln => [
      `"${vuln.title.replace(/"/g, '""')}"`,
      vuln.severity,
      vuln.cvss,
      vuln.cwe,
      vuln.count,
      `"${vuln.description.replace(/"/g, '""')}"`,
      `"${vuln.remediation.replace(/"/g, '""')}"`,
      `"${vuln.instances.map(i => i.location).join(', ')}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8,"
      + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    const targetName = scanStats.target.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    link.setAttribute("download", `scan_report_${targetName}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const techVulnerabilities: TechnologyFinding[] = allVulnerabilities.filter(v => v.category === 'technology-fingerprint');

  const groupedTech = techVulnerabilities.reduce((acc, finding) => {
    const tech = finding.title || 'Unknown Technology';
    if (!acc[tech]) {
      acc[tech] = [];
    }
    // Assuming description contains version, etc.
    acc[tech].push(finding);
    return acc;
  }, {} as Record<string, TechnologyFinding[]>);

  const getSeverityClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-800 text-red-200 border-red-600';
      case 'high':
        return 'bg-orange-800 text-orange-200 border-orange-600';
      case 'medium':
        return 'bg-yellow-800 text-yellow-200 border-yellow-600';
      case 'low':
        return 'bg-blue-800 text-blue-200 border-blue-600';
      default:
        return 'bg-gray-700 text-gray-200 border-gray-600';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex justify-center items-center z-50 p-4">
      <div className="bg-background text-text w-full max-w-4xl h-full max-h-[90vh] rounded-lg shadow-2xl flex flex-col">
        <header className="bg-surface p-4 flex justify-between items-center rounded-t-lg">
          <h1 className="text-2xl font-bold">Scan Report</h1>
          <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-700">
            <X size={24} />
          </button>
        </header>

        <main ref={reportContentRef} className="p-8 overflow-y-auto">
          {/* Scan Summary */}
          <section className="mb-8 p-6 bg-surface rounded-lg">
            <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-sm text-textSecondary">Target</p>
                <p className="font-semibold truncate" title={scanStats.target}>{scanStats.target}</p>
              </div>
              <div>
                <p className="text-sm text-textSecondary">Scan Date</p>
                <p className="font-semibold">{scanStats.lastScan}</p>
              </div>
              <div>
                <p className="text-sm text-textSecondary">Duration</p>
                <p className="font-semibold">{scanStats.scanDuration}</p>
              </div>
              <div>
                <p className="text-sm text-textSecondary">URLs Scanned</p>
                <p className="font-semibold">{scanStats.urlsScanned}</p>
              </div>
            </div>
          </section>

          {/* Technology Stack */}
          <section className="mb-8 p-6 bg-surface rounded-lg">
            <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">Technology Stack</h2>
            {Object.keys(groupedTech).length > 0 ? (
              <ul className="space-y-2">
                {Object.entries(groupedTech).map(([tech, findings]) => (
                  <li key={tech} className="flex items-center text-sm">
                    <span className="font-bold w-40">{tech}:</span>
                    <span>{findings.map(f => f.description).join(', ')}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-textSecondary">No specific technologies identified.</p>
            )}
          </section>

          {/* Vulnerabilities */}
          <section>
            <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">Vulnerabilities Found ({groupedVulnerabilities.length})</h2>
            <div className="space-y-6">
              {groupedVulnerabilities.map((vuln) => (
                <div key={vuln.groupKey} className="bg-surface p-6 rounded-lg">
                  <h3 className="text-lg font-bold mb-3">{vuln.title}</h3>
                  <div className="flex items-center space-x-4 mb-4">
                    <span className={`px-3 py-1 text-sm font-semibold rounded-full border ${getSeverityClass(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                    <span className="text-sm text-textSecondary">CWE: {vuln.cwe}</span>
                    <span className="text-sm text-textSecondary">CVSS: {vuln.cvss.toFixed(1)}</span>
                    <span className="text-sm text-textSecondary">Found {vuln.count} time(s)</span>
                  </div>
                  <p className="text-sm mb-4">{vuln.description}</p>

                  <div className="bg-background p-4 rounded-md">
                    <h4 className="font-semibold mb-2">Affected Locations:</h4>
                    <ul className="list-disc list-inside text-sm font-mono max-h-32 overflow-y-auto">
                      {vuln.instances.map((instance, index) => (
                        <li key={index} className="truncate" title={instance.location}>{instance.location}</li>
                      ))}
                    </ul>
                  </div>

                </div>
              ))}
            </div>
          </section>
        </main>

        <footer className="bg-surface p-4 mt-auto rounded-b-lg flex justify-end space-x-4">
          <button
            onClick={handleDownloadCsv}
            className="bg-gray-600 hover:bg-gray-500 text-white font-bold py-2 px-4 rounded-md flex items-center"
          >
            <Download size={18} className="mr-2" />
            Download CSV
          </button>
          <button
            onClick={handleDownloadPdf}
            className="bg-primary hover:bg-opacity-80 text-background font-bold py-2 px-4 rounded-md flex items-center"
          >
            <Download size={18} className="mr-2" />
            Download PDF
          </button>
        </footer>
        {/* Modal Form for User Info */}
        {showForm && (
          <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
            <form onSubmit={handleFormSubmit} className="bg-surface p-8 rounded-lg shadow-lg w-full max-w-md flex flex-col space-y-4">
              <h2 className="text-xl font-bold mb-2">Enter your business email to download the PDF</h2>
              <input
                type="email"
                name="email"
                placeholder="Business Email"
                value={formData.email}
                onChange={handleFormChange}
                className="p-2 rounded border border-gray-600 bg-background text-text"
                required
              />
              <div className="text-sm text-textSecondary">Scan URL: <span className="font-mono">{scanStats.target}</span></div>
              {formError && <div className="text-error text-sm">{formError}</div>}
              <div className="flex justify-end space-x-2 mt-4">
                <button type="button" onClick={() => setShowForm(false)} className="px-4 py-2 rounded bg-gray-700 text-white">Cancel</button>
                <button type="submit" disabled={isSubmitting} className="px-4 py-2 rounded bg-primary text-background font-bold">
                  {isSubmitting ? 'Submitting...' : 'Submit & Download PDF'}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanReport; 