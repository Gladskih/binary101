"use strict";

type QueueWaiter<T> = (value: T | null) => void;

class AsyncQueue<T> {
  private readonly values: T[] = [];
  private readonly itemWaiters: Array<QueueWaiter<T>> = [];
  private readonly capacityWaiters: Array<() => void> = [];
  private closed = false;
  constructor(private readonly capacity = Number.MAX_SAFE_INTEGER) {}
  async push(value: T): Promise<boolean> {
    while (!this.closed && this.values.length >= this.capacity) {
      await new Promise<void>(resolve => this.capacityWaiters.push(resolve));
    }
    if (this.closed) return false;
    const waiter = this.itemWaiters.shift();
    if (waiter) waiter(value);
    else this.values.push(value);
    return true;
  }
  async shift(): Promise<T | null> {
    const value = this.values.shift();
    if (value !== undefined) {
      this.wakeCapacityWaiter();
      return value;
    }
    if (this.closed) return null;
    return new Promise<T | null>(resolve => this.itemWaiters.push(resolve));
  }
  takeAvailable(limit: number): T[] {
    const count = Math.max(0, Math.min(Math.trunc(limit), this.values.length));
    const values = this.values.splice(0, count);
    for (let index = 0; index < values.length; index += 1) this.wakeCapacityWaiter();
    return values;
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    while (this.itemWaiters.length) this.itemWaiters.shift()?.(null);
    while (this.capacityWaiters.length) this.capacityWaiters.shift()?.();
  }
  closeAndDiscard(): void {
    this.values.length = 0;
    this.close();
  }
  private wakeCapacityWaiter(): void {
    this.capacityWaiters.shift()?.();
  }
}

export { AsyncQueue };
