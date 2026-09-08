/**
 * UI State Management, DOM Helpers, and Metrics Formatting Module.
 *
 * Security & Reliability:
 * 1. Strict XSS Prevention: All dynamic text values (filenames, peer IDs, device names, error messages)
 *    are assigned via element.textContent or sanitized.
 * 2. Throttled DOM Updates: Progress meter updates throttled to avoid rendering bottlenecks.
 * 3. State Machine Integrity: Enforces explicit receiver approval gate prior to TRANSFERRING state.
 */

/**
 * Format bytes into human-readable string (B, KB, MB, GB).
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (typeof bytes !== 'number' || isNaN(bytes) || bytes <= 0) {
    return '0 B';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  if (i === 0) {
    return `${bytes} B`;
  }

  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(2)} ${units[i]}`;
}

/**
 * Format transfer speed in bytes per second.
 * @param {number} bytesPerSecond
 * @returns {string}
 */
export function formatSpeed(bytesPerSecond) {
  if (typeof bytesPerSecond !== 'number' || isNaN(bytesPerSecond) || bytesPerSecond <= 0) {
    return '0 B/s';
  }
  return `${formatBytes(bytesPerSecond)}/s`;
}

/**
 * Format duration in seconds into human-readable time string.
 * @param {number} seconds
 * @returns {string}
 */
export function formatDuration(seconds) {
  if (typeof seconds !== 'number' || isNaN(seconds) || seconds <= 0) {
    return '0s';
  }

  const totalSecs = Math.round(seconds);
  const hours = Math.floor(totalSecs / 3600);
  const minutes = Math.floor((totalSecs % 3600) / 60);
  const secs = totalSecs % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

/**
 * Calculate estimated time remaining (ETA).
 * @param {Object} params
 * @param {number} params.totalBytes
 * @param {number} params.transferredBytes
 * @param {number} params.bytesPerSecond
 * @returns {number | null} Seconds remaining or null if undetermined
 */
export function calculateETA({ totalBytes, transferredBytes, bytesPerSecond }) {
  if (typeof bytesPerSecond !== 'number' || bytesPerSecond <= 0) {
    return null;
  }
  if (transferredBytes >= totalBytes) {
    return 0;
  }
  const remainingBytes = totalBytes - transferredBytes;
  return Math.ceil(remainingBytes / bytesPerSecond);
}

/**
 * Escape special HTML characters to prevent XSS injection.
 * @param {string} str
 * @returns {string}
 */
export function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

export const UIStates = {
  IDLE: 'IDLE',
  SELECTING_FILES: 'SELECTING_FILES',
  PAIRING: 'PAIRING',
  CONNECTED: 'CONNECTED',
  WAITING_APPROVAL: 'WAITING_APPROVAL',
  TRANSFERRING: 'TRANSFERRING',
  PAUSED: 'PAUSED',
  VERIFYING: 'VERIFYING',
  COMPLETED: 'COMPLETED',
  CANCELLED: 'CANCELLED',
  ERROR: 'ERROR'
};

const VALID_TRANSITIONS = {
  [UIStates.IDLE]: [UIStates.SELECTING_FILES, UIStates.PAIRING, UIStates.CONNECTED, UIStates.WAITING_APPROVAL, UIStates.TRANSFERRING, UIStates.ERROR],
  [UIStates.SELECTING_FILES]: [UIStates.IDLE, UIStates.PAIRING, UIStates.CONNECTED, UIStates.WAITING_APPROVAL, UIStates.TRANSFERRING, UIStates.ERROR],
  [UIStates.PAIRING]: [UIStates.CONNECTED, UIStates.WAITING_APPROVAL, UIStates.TRANSFERRING, UIStates.IDLE, UIStates.CANCELLED, UIStates.ERROR],
  [UIStates.CONNECTED]: [UIStates.WAITING_APPROVAL, UIStates.TRANSFERRING, UIStates.PAIRING, UIStates.IDLE, UIStates.SELECTING_FILES, UIStates.CANCELLED, UIStates.ERROR],
  [UIStates.WAITING_APPROVAL]: [UIStates.TRANSFERRING, UIStates.CANCELLED, UIStates.ERROR, UIStates.IDLE],
  [UIStates.TRANSFERRING]: [UIStates.VERIFYING, UIStates.PAUSED, UIStates.CANCELLED, UIStates.ERROR],
  [UIStates.PAUSED]: [UIStates.TRANSFERRING, UIStates.CANCELLED, UIStates.ERROR],
  [UIStates.VERIFYING]: [UIStates.COMPLETED, UIStates.CANCELLED, UIStates.ERROR],
  [UIStates.COMPLETED]: [UIStates.IDLE, UIStates.PAIRING, UIStates.SELECTING_FILES],
  [UIStates.CANCELLED]: [UIStates.IDLE, UIStates.PAIRING, UIStates.SELECTING_FILES],
  [UIStates.ERROR]: [UIStates.IDLE, UIStates.PAIRING, UIStates.SELECTING_FILES]
};

/**
 * Manages UI application lifecycle states with receiver approval gating.
 */
export class UIStateManager {
  constructor(initialState = UIStates.IDLE) {
    this.state = initialState;
    this.errorMessage = null;
    this.isApproved = false;
    this.listeners = new Set();
  }

  getState() {
    return this.state;
  }

  getErrorMessage() {
    return this.errorMessage;
  }

  onStateChange(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  approve() {
    this.isApproved = true;
  }

  transition(nextState) {
    if (this.state === nextState) return;

    // Strict Receiver Approval Enforcement
    if (nextState === UIStates.TRANSFERRING && !this.isApproved) {
      throw new Error('Receiver approval required before transitioning to TRANSFERRING state');
    }

    const allowed = VALID_TRANSITIONS[this.state] || [];
    if (!allowed.includes(nextState)) {
      throw new Error(`Invalid state transition: from ${this.state} to ${nextState}`);
    }

    this.state = nextState;
    this._emit();
  }

  cancel(reason = 'Transfer cancelled') {
    this.state = UIStates.CANCELLED;
    this.errorMessage = reason;
    this._emit();
  }

  error(errorMsg = 'An unexpected error occurred') {
    this.state = UIStates.ERROR;
    this.errorMessage = typeof errorMsg === 'string' ? errorMsg : errorMsg?.message || 'Unknown error';
    this._emit();
  }

  reset() {
    this.state = UIStates.IDLE;
    this.errorMessage = null;
    this.isApproved = false;
    this._emit();
  }

  _emit() {
    for (const listener of this.listeners) {
      try {
        listener(this.state, this.errorMessage);
      } catch (err) {
        console.error('Error in UIStateManager listener:', err);
      }
    }
  }
}

/**
 * Create a throttled progress runner to prevent DOM thrashing during high-speed chunk streaming.
 *
 * @param {Object} options
 * @param {(progress: Object) => void} options.onUpdate
 * @param {number} [options.intervalMs=80]
 */
export function createProgressThrottler({ onUpdate, intervalMs = 80 }) {
  let lastUpdate = 0;
  let pendingProgress = null;
  let timeoutId = null;

  return {
    update(progress) {
      pendingProgress = progress;
      const now = Date.now();

      if (now - lastUpdate >= intervalMs) {
        lastUpdate = now;
        if (timeoutId) {
          clearTimeout(timeoutId);
          timeoutId = null;
        }
        onUpdate(progress);
      } else if (!timeoutId) {
        timeoutId = setTimeout(() => {
          lastUpdate = Date.now();
          timeoutId = null;
          if (pendingProgress) {
            onUpdate(pendingProgress);
          }
        }, intervalMs - (now - lastUpdate));
      }
    },

    flush() {
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (pendingProgress) {
        onUpdate(pendingProgress);
      }
    },

    reset() {
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      pendingProgress = null;
      lastUpdate = 0;
    }
  };
}

/**
 * Safe DOM text assignment helper.
 * @param {HTMLElement | string} target
 * @param {string} text
 */
export function setElementText(target, text) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (el) {
    el.textContent = text !== undefined && text !== null ? String(text) : '';
  }
}
