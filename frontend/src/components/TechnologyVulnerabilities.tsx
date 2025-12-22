import React from 'react';
import { Layers } from 'lucide-react';
import { VulnerabilityData } from './VulnerabilityList'; // Reuse the interface

interface TechnologyVulnerabilitiesProps {
  vulnerabilities: VulnerabilityData[];
}

const getSeverityClass = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
    case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
    case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
    case 'low': return 'text-sky-400 bg-sky-400/10 border-sky-400/20';
    case 'info': return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
    default: return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
  }
};

const TechnologyVulnerabilities: React.FC<TechnologyVulnerabilitiesProps> = ({ vulnerabilities }) => {
  return (
    <div className="bg-surface rounded-lg p-3">
      <div className="flex items-center mb-3">
        <Layers className="h-5 w-5 text-primary mr-2" />
        <h2 className="text-lg font-bold text-text">Technology Stack & Known Vulnerabilities</h2>
      </div>
      <div className="space-y-2 max-h-52 overflow-y-auto">
        {vulnerabilities.map((vuln) => (
          <div key={vuln.id || vuln.title} className="bg-background p-2 rounded-md border-l-4 border-primary/50">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-1">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${getSeverityClass(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                  <span className="text-xs text-textSecondary bg-surface px-2 py-0.5 rounded">
                    {vuln.cwe}
                  </span>
                  <span className="text-xs text-textSecondary bg-surface px-2 py-0.5 rounded">
                    {vuln.cve}
                  </span>
                </div>
                <h4 className="font-medium text-text-sm mb-0.5">{vuln.title}</h4>
                <p className="text-xs text-textSecondary">{vuln.description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default TechnologyVulnerabilities; 