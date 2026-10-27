/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the shared `Memo` helper: one resolution shared by
 * concurrent callers, a rejection dropped so the next call retries, a
 * rejection `retain` claims replayed instead, and `reset()`.
 */
import { describe, it, expect } from 'vitest'

import { Memo } from '../../src/internal/memo.js'

describe('Memo', () => {
  it('shares one in-flight resolution and caches the value', async () => {
    let calls = 0
    const memo = new Memo(async () => {
      calls += 1
      return 'value'
    })
    expect(memo.started).toBe(false)
    const [first, second] = await Promise.all([memo.get(), memo.get()])
    expect(first).toBe('value')
    expect(second).toBe('value')
    expect(memo.started).toBe(true)
    await memo.get()
    expect(calls).toBe(1)
  })

  it('drops a rejection so the next get() retries', async () => {
    let calls = 0
    const memo = new Memo(async () => {
      calls += 1
      if (calls === 1) {
        throw new Error('transient')
      }
      return 'recovered'
    })
    await expect(memo.get()).rejects.toThrow('transient')
    await expect(memo.get()).resolves.toBe('recovered')
    expect(calls).toBe(2)
  })

  it('keeps a rejection retain claims and replays it without re-resolving', async () => {
    let calls = 0
    const permanent = new Error('permanent')
    const memo = new Memo(
      async () => {
        calls += 1
        throw permanent
      },
      { retain: err => err === permanent }
    )
    const first = await memo.get().catch((err: unknown) => err)
    const second = await memo.get().catch((err: unknown) => err)
    expect(first).toBe(permanent)
    expect(second).toBe(permanent)
    expect(calls).toBe(1)
    // reset() drops a retained rejection like any other held resolution.
    memo.reset()
    await memo.get().catch(() => undefined)
    expect(calls).toBe(2)
  })
})
