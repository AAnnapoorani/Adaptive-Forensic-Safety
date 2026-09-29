export function parseUtcDate(dateStr?: string | null): Date | null {
  if (!dateStr) return null;
  // If string has no timezone indicator (no 'Z' and no '+' or '-'), treat as UTC
  let normalized = dateStr.trim();
  if (!normalized.endsWith('Z') && !normalized.includes('+') && !normalized.includes('-', 10)) {
    normalized = `${normalized}Z`;
  }
  const d = new Date(normalized);
  return isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(dateStr?: string | null): string {
  const d = parseUtcDate(dateStr);
  if (!d) return 'N/A';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}

export function formatTime(dateStr?: string | null): string {
  const d = parseUtcDate(dateStr);
  if (!d) return '--:--:--';
  return d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}

export function formatRelative(dateStr?: string | null): string {
  const d = parseUtcDate(dateStr);
  if (!d) return '';
  const now = new Date();
  const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}
