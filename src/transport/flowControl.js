/**
 * WebRTC DataChannel Flow Control and Backpressure Manager.
 *
 * Prevents memory blowup and socket buffer overflow when sending large files over RTCDataChannel.
 * Monitors `bufferedAmount` against high and low water marks.
 */

export const DEFAULT_HIGH_WATER_MARK = 128 * 1024; // 128 KB (Wi-Fi safe, anti-bufferbloat: 2x 64KB chunks max)
export const DEFAULT_LOW_WATER_MARK = 32 * 1024;   // 32 KB (resumes as soon as 1 chunk clears)

export class FlowController {
  /**
   * @param {Object} [options]
   * @param {number} [options.highWaterMark=131072] - Maximum buffered bytes before pausing
   * @param {number} [options.lowWaterMark=32768]   - Threshold to resume sending
   */
  constructor({
    highWaterMark = DEFAULT_HIGH_WATER_MARK,
    lowWaterMark = DEFAULT_LOW_WATER_MARK
  } = {}) {
    if (lowWaterMark >= highWaterMark) {
      throw new Error('lowWaterMark must be strictly less than highWaterMark');
    }
    this.highWaterMark = highWaterMark;
    this.lowWaterMark = lowWaterMark;
  }

  /**
   * Configure threshold on RTCDataChannel.
   * @param {RTCDataChannel} channel
   */
  configureChannel(channel) {
    if (!channel) return;
    try {
      channel.bufferedAmountLowThreshold = this.lowWaterMark;
    } catch {
      // Ignored if mock or unsupported
    }
  }

  /**
   * Determine if sending should be paused due to buffer backpressure.
   * @param {RTCDataChannel} channel
   * @returns {boolean}
   */
  shouldWait(channel) {
    if (!channel) return false;
    return (channel.bufferedAmount || 0) >= this.highWaterMark;
  }

  /**
   * Pause execution until bufferedAmount drops below lowWaterMark.
   * @param {RTCDataChannel} channel
   * @param {number} [timeoutMs=30000] - Safety timeout to prevent deadlock
   * @returns {Promise<void>}
   */
  async waitForDrain(channel, timeoutMs = 30000) {
    if (!channel || channel.readyState !== 'open') {
      return;
    }

    if (!this.shouldWait(channel)) {
      return;
    }

    return new Promise((resolve, reject) => {
      let timeoutTimer = null;
      let pollTimer = null;

      const addListener = (target, evt, fn) => {
        if (typeof target.addEventListener === 'function') target.addEventListener(evt, fn);
        else if (typeof target.on === 'function') target.on(evt, fn);
      };

      const removeListener = (target, evt, fn) => {
        if (typeof target.removeEventListener === 'function') target.removeEventListener(evt, fn);
        else if (typeof target.removeListener === 'function') target.removeListener(evt, fn);
        else if (typeof target.off === 'function') target.off(evt, fn);
      };

      const cleanup = () => {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        if (pollTimer) clearInterval(pollTimer);
        removeListener(channel, 'bufferedamountlow', onLow);
        removeListener(channel, 'close', onClose);
        removeListener(channel, 'error', onError);
      };

      const onLow = () => {
        cleanup();
        resolve();
      };

      const onClose = () => {
        cleanup();
        reject(new Error('DataChannel closed while waiting for buffer drain'));
      };

      const onError = (ev) => {
        cleanup();
        const msg = (ev?.message || String(ev || '')).toLowerCase();
        if (msg.includes('user-initiated abort') || msg.includes('close called')) {
          resolve();
          return;
        }
        reject(new Error(`DataChannel error during drain: ${ev?.message || 'unknown'}`));
      };

      addListener(channel, 'bufferedamountlow', onLow);
      addListener(channel, 'close', onClose);
      addListener(channel, 'error', onError);

      // Active polling fallback: Mobile/Wi-Fi browsers sometimes delay or drop the
      // 'bufferedamountlow' event. Polling unblocks immediately when bufferedAmount <= lowWaterMark.
      pollTimer = setInterval(() => {
        if (!channel || channel.readyState !== 'open') {
          return;
        }
        if ((channel.bufferedAmount || 0) <= this.lowWaterMark) {
          cleanup();
          resolve();
        }
      }, 15);
      if (pollTimer && typeof pollTimer.unref === 'function') {
        pollTimer.unref();
      }

      timeoutTimer = setTimeout(() => {
        cleanup();
        // Even if timeout triggered, proceed to avoid permanent deadlock
        resolve();
      }, timeoutMs);
      if (timeoutTimer && typeof timeoutTimer.unref === 'function') {
        timeoutTimer.unref();
      }
    });
  }
}
