import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import App from './App';
import * as scanApi from './api/scanApi';

// Helper to flush all pending promises
function flushPromises() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

describe('App scan timeout behavior', () => {
  it('shows timeout message if scan takes longer than 120 seconds', async () => {
    // Mock startScan to never resolve
    vi.spyOn(scanApi, 'startScan').mockImplementation(() => new Promise(() => { }));

    render(<App />);
    const input = screen.getByPlaceholderText(/http/i);
    fireEvent.change(input, { target: { value: 'http://example.com' } });
    const startButton = screen.getByText(/Start Scan/i);
    fireEvent.click(startButton);

    // Fast-forward timers by 120s
    vi.useFakeTimers();
    vi.advanceTimersByTime(120_000);
    await flushPromises();
    vi.useRealTimers();

    await waitFor(() => {
      expect(screen.getByText(/Scan timed out after 120 seconds/i)).toBeInTheDocument();
    });
  });
});

describe('App conditional rendering', () => {
  it('shows only URL input and Start Scan on initial render', () => {
    render(<App />);
    expect(screen.getByPlaceholderText(/http/i)).toBeInTheDocument();
    expect(screen.getByText(/Start Scan/i)).toBeInTheDocument();
    // Scanner selector and Scan History should not be visible
    expect(screen.queryByText(/Available Scanners/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Scan History/i)).not.toBeInTheDocument();
  });

  it('reveals scanner selector and panels after URL is submitted', async () => {
    vi.spyOn(scanApi, 'startScan').mockResolvedValue({ scan_id: 'test123', status: 'started' });
    render(<App />);
    const input = screen.getByPlaceholderText(/http/i);
    fireEvent.change(input, { target: { value: 'http://example.com' } });
    const startButton = screen.getByText(/Start Scan/i);
    fireEvent.click(startButton);
    await waitFor(() => {
      expect(screen.getByText(/Available Scanners/i)).toBeInTheDocument();
      expect(screen.getByText(/Scan History/i)).toBeInTheDocument();
    });
  });
}); 