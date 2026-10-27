/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared "memoize an in-flight promise, but only cache a success" helper.
 * Several lazily-resolved singletons across the client -- a handle's codec,
 * the service description, a lazily-unwrapped epoch key -- want the same three
 * properties: concurrent callers share one round-trip, a rejection is not
 * cached (so the next call retries rather than replaying a stale failure), and
 * a reset drops whatever is held. Written once here so the three cannot drift
 * apart, which they had. A user whose input cannot change under it may name
 * the rejections it wants kept, so a permanent failure is raised once and then
 * replayed instead of re-attempted.
 */

/**
 * A memo of one lazily-resolved value. Holds the in-flight promise so
 * concurrent callers share a single resolution, drops it on rejection so a
 * transient failure does not permanently poison the memo (unless `retain`
 * claims that rejection), and exposes {@link Memo.reset} for when the
 * underlying answer is known to have changed.
 */
export class Memo<T> {
  #promise?: Promise<T>
  readonly #resolve: () => Promise<T>
  readonly #retain: (err: unknown) => boolean

  /**
   * @param resolve {function}   resolves a fresh value; re-invoked after a
   *   rejection or a `reset()`, else called at most once
   * @param [options] {object}
   * @param [options.retain] {function}   given a rejection's reason, whether
   *   to keep that rejection memoized (a failure a retry cannot change);
   *   default: keep none
   */
  constructor(
    resolve: () => Promise<T>,
    { retain = () => false }: { retain?: (err: unknown) => boolean } = {}
  ) {
    this.#resolve = resolve
    this.#retain = retain
  }

  /**
   * Whether a resolution is already held -- in flight or settled. Lets a caller
   * tell, synchronously and before calling {@link Memo.get}, whether its own
   * call is the one that starts the resolution.
   *
   * @returns {boolean}
   */
  get started(): boolean {
    return this.#promise !== undefined
  }

  /**
   * Returns the memoized value, resolving it on first use.
   *
   * @returns {Promise<T>}
   */
  get(): Promise<T> {
    if (this.#promise) {
      return this.#promise
    }
    const promise = this.#resolve()
    // Memoize the in-flight promise so concurrent callers share one round-trip,
    // but drop it on rejection so a transient failure does not permanently
    // poison the memo. A rejection `retain` claims stays, so the next `get()`
    // replays it rather than paying for an attempt that can only fail the same
    // way. The identity guard avoids clobbering a newer promise.
    this.#promise = promise
    promise.catch((err: unknown): void => {
      if (this.#promise === promise && !this.#retain(err)) {
        this.#promise = undefined
      }
    })
    return promise
  }

  /**
   * Drops any memoized value so the next `get()` re-resolves.
   *
   * @returns {void}
   */
  reset(): void {
    this.#promise = undefined
  }
}
