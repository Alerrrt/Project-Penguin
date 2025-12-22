import React, { useEffect, useRef } from 'react';

// Assuming LogEntry is defined in your context, otherwise define it here
interface LogEntry {
  timestamp: string;
  message: string;
}

interface LiveModuleStatusProps {
  activityLogs: LogEntry[];
}

const parseLogMessage = (message: string): { icon: string; color: string; content: string } => {
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('error') || lowerMessage.includes('failed')) {
    return { icon: '[!]', color: 'text-red-400', content: message };
  }
  if (lowerMessage.startsWith('[+] new finding:')) {
    const details = message.substring('[+] new finding:'.length).trim();
    return { icon: '[+]', color: 'text-yellow-300', content: `New Finding: ${details}` };
  }
  if (lowerMessage.includes('=> completed')) {
    return { icon: '[]', color: 'text-green-400', content: message };
  }
  if (lowerMessage.includes('=> running') || lowerMessage.includes('executing scanner')) {
    return { icon: '[»]', color: 'text-blue-400', content: message };
  }
  
  return { icon: '[i]', color: 'text-gray-400', content: message };
};

const LiveModuleStatus: React.FC<LiveModuleStatusProps> = ({ activityLogs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [activityLogs]);

  if (activityLogs.length === 0) {
    return null; // Don't render if there are no logs
  }

  // Only show the last 50 logs for better performance
  const visibleLogs = activityLogs.slice(-50);

  return (
    <div className="bg-surface rounded-lg p-4 font-mono text-xs h-96 overflow-y-auto" ref={scrollRef}>
      <h2 className="text-lg font-bold text-text mb-2 sticky top-0 bg-surface pb-2">
        Live Activity ({activityLogs.length} total)
      </h2>
      {visibleLogs.map((log, index) => {
        const { icon, color, content } = parseLogMessage(log.message);
        return (
          <div key={`${log.timestamp}-${index}`} className="flex items-start">
            <span className="text-gray-500 mr-3 flex-shrink-0">
              {new Date(log.timestamp).toLocaleTimeString()}
            </span>
            <span className={`${color} font-bold mr-2 flex-shrink-0`}>{icon}</span>
            <span className={`${color} flex-1 whitespace-pre-wrap break-words`}>
              {content}
            </span>
          </div>
        );
      })}
    </div>
  );
};

export default React.memo(LiveModuleStatus); 