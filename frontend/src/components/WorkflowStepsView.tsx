import React from 'react';
import { ListOrdered, CheckCircle2, Clock, AlertCircle } from 'lucide-react';

interface WorkflowStepsViewProps {
  steps: Array<{
    id: string;
    operation: string;
    priority: number;
    status: string;
    start_time?: string;
    end_time?: string;
    result_summary?: string;
    error_message?: string;
  }>;
}

export const WorkflowStepsView: React.FC<WorkflowStepsViewProps> = ({ steps }) => {
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <span className="badge badge-completed"><CheckCircle2 size={12} /> COMPLETED</span>;
      case 'RUNNING':
        return <span className="badge badge-in-progress"><Clock size={12} /> EXECUTING</span>;
      case 'FAILED':
        return <span className="badge badge-failed"><AlertCircle size={12} /> FAILED</span>;
      default:
        return <span className="badge badge-neutral">PENDING</span>;
    }
  };

  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ListOrdered size={18} color="#38bdf8" />
            Executable Workflow Operations Ledger
          </h3>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            Ordered compilation of forensic collector routines executed across investigation rounds.
          </p>
        </div>
        <span className="badge badge-in-progress">{steps.length} Steps</span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Operation</th>
              <th>Status</th>
              <th>Start Time</th>
              <th>End Time</th>
              <th>Result / Outcome</th>
            </tr>
          </thead>
          <tbody>
            {steps.map(step => (
              <tr key={step.id}>
                <td>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 24,
                    height: 24,
                    borderRadius: 6,
                    background: step.priority === 1 ? 'rgba(2, 132, 199, 0.15)' : 'var(--bg-item)',
                    color: step.priority === 1 ? 'var(--accent-blue)' : 'var(--text-main)',
                    border: '1px solid var(--border-subtle)',
                    fontWeight: 700,
                    fontSize: 12
                  }}>
                    {step.priority}
                  </span>
                </td>
                <td>
                  <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{step.operation}</span>
                </td>
                <td>{getStatusBadge(step.status)}</td>
                <td>
                  <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    {step.start_time ? new Date(step.start_time).toLocaleTimeString() : '—'}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    {step.end_time ? new Date(step.end_time).toLocaleTimeString() : '—'}
                  </span>
                </td>
                <td>
                  {step.error_message ? (
                    <span style={{ color: 'var(--accent-rose)', fontSize: 12, fontWeight: 500 }}>{step.error_message}</span>
                  ) : (
                    <span style={{ color: 'var(--text-main)', fontSize: 12 }}>{step.result_summary || 'Pending execution'}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
