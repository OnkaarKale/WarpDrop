/**
 * Transfer Protocol State Machine.
 *
 * Enforces strictly valid state transitions for sender and receiver roles,
 * with explicit user approval gating before file chunk transmission.
 */

export const TransferStates = Object.freeze({
  IDLE: 'IDLE',
  MANIFEST_SENT: 'MANIFEST_SENT',
  MANIFEST_RECEIVED: 'MANIFEST_RECEIVED',
  AWAITING_APPROVAL: 'AWAITING_APPROVAL',
  ACCEPTED: 'ACCEPTED',
  TRANSFERRING: 'TRANSFERRING',
  PAUSED: 'PAUSED',
  VERIFYING: 'VERIFYING',
  COMPLETED: 'COMPLETED',
  CANCELLED: 'CANCELLED',
  ERROR: 'ERROR'
});

const ALLOWED_TRANSITIONS = {
  [TransferStates.IDLE]: [
    TransferStates.MANIFEST_SENT,
    TransferStates.MANIFEST_RECEIVED,
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.MANIFEST_SENT]: [
    TransferStates.TRANSFERRING, // Initiator starts transferring once receiver ACKs accept
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.MANIFEST_RECEIVED]: [
    TransferStates.AWAITING_APPROVAL, // Must prompt user for approval
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.AWAITING_APPROVAL]: [
    TransferStates.ACCEPTED, // User clicks Accept
    TransferStates.CANCELLED, // User clicks Reject
    TransferStates.ERROR
  ],
  [TransferStates.ACCEPTED]: [
    TransferStates.TRANSFERRING, // Receiver begins accepting incoming chunks
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.TRANSFERRING]: [
    TransferStates.PAUSED,
    TransferStates.VERIFYING,
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.PAUSED]: [
    TransferStates.TRANSFERRING,
    TransferStates.CANCELLED,
    TransferStates.ERROR
  ],
  [TransferStates.VERIFYING]: [
    TransferStates.COMPLETED,
    TransferStates.ERROR
  ],
  [TransferStates.COMPLETED]: [],
  [TransferStates.CANCELLED]: [],
  [TransferStates.ERROR]: []
};

export class TransferStateMachine {
  /**
   * @param {'sender' | 'receiver'} role
   */
  constructor(role = 'sender') {
    this.role = role;
    this.state = TransferStates.IDLE;
    this.listeners = new Set();
  }

  getState() {
    return this.state;
  }

  /**
   * Transition to a new state with strict validation.
   * @param {string} nextState
   * @param {string} [reason]
   */
  transition(nextState, reason = '') {
    const validTargets = ALLOWED_TRANSITIONS[this.state] || [];
    if (!validTargets.includes(nextState)) {
      throw new Error(
        `Illegal transition in state machine: cannot move from ${this.state} to ${nextState}. Reason: ${reason || 'unspecified'}`
      );
    }

    const previousState = this.state;
    this.state = nextState;
    this._notify(previousState, nextState, reason);
  }

  approve() {
    if (this.state !== TransferStates.AWAITING_APPROVAL && this.state !== TransferStates.MANIFEST_RECEIVED) {
      throw new Error(`Cannot approve transfer in state ${this.state}`);
    }
    if (this.state === TransferStates.MANIFEST_RECEIVED) {
      this.transition(TransferStates.AWAITING_APPROVAL);
    }
    this.transition(TransferStates.ACCEPTED);
  }

  cancel(reason = 'User cancelled') {
    if (this.state === TransferStates.COMPLETED || this.state === TransferStates.CANCELLED) {
      return;
    }
    this.transition(TransferStates.CANCELLED, reason);
  }

  error(err) {
    if (this.state === TransferStates.COMPLETED || this.state === TransferStates.CANCELLED) {
      return;
    }
    const message = err?.message || String(err);
    this.transition(TransferStates.ERROR, message);
  }

  onChange(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  _notify(from, to, reason) {
    for (const listener of this.listeners) {
      try {
        listener({ from, to, reason });
      } catch {
        // Prevent listener failures from breaking state machine
      }
    }
  }
}
