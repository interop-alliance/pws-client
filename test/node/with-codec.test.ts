/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `withCodec`, the overlap of codec resolution with the read
 * it decodes: the codec failure takes precedence, the abandoned read's
 * rejection is not left unhandled, and the abandoned read's body is cancelled
 * so a non-JSON response does not hold its connection open.
 */
import { describe, it, expect, vi } from 'vitest'

import type { ResourceCodec } from '../../src/codec.js'
import { withCodec } from '../../src/internal/withCodec.js'

const codec = {} as ResourceCodec

/**
 * A response-shaped object with a cancellable body stream and a `cancel` spy.
 *
 * @param options {object}
 * @param [options.bodyUsed] {boolean}   whether the body reads as consumed
 * @returns {object}
 */
function responseWithBody({ bodyUsed = false }: { bodyUsed?: boolean } = {}) {
  const cancel = vi.fn(async () => {})
  const body = new ReadableStream<Uint8Array>({ cancel })
  return { response: { body, bodyUsed }, cancel }
}

/**
 * Lets the microtasks queued by a settled promise run.
 *
 * @returns {Promise<void>}
 */
async function settle(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0))
}

describe('withCodec', () => {
  it('returns both once they settle', async () => {
    const { response } = responseWithBody()
    const result = await withCodec(
      Promise.resolve(codec),
      Promise.resolve(response)
    )
    expect(result).toEqual([codec, response])
  })

  it('cancels the response body when the codec rejects', async () => {
    const { response, cancel } = responseWithBody()
    await expect(
      withCodec(
        Promise.reject(new Error('no codec')),
        Promise.resolve(response)
      )
    ).rejects.toThrow('no codec')
    await settle()
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('cancels the body of a response that arrives after the codec failed', async () => {
    const { response, cancel } = responseWithBody()
    let deliver!: (value: typeof response) => void
    const late = new Promise<typeof response>(resolve => {
      deliver = resolve
    })
    await expect(
      withCodec(Promise.reject(new Error('no codec')), late)
    ).rejects.toThrow('no codec')
    expect(cancel).not.toHaveBeenCalled()
    deliver(response)
    await settle()
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('leaves a consumed body and a null read alone', async () => {
    const { response, cancel } = responseWithBody({ bodyUsed: true })
    await expect(
      withCodec(
        Promise.reject(new Error('no codec')),
        Promise.resolve(response)
      )
    ).rejects.toThrow('no codec')
    await expect(
      withCodec(Promise.reject(new Error('no codec')), Promise.resolve(null))
    ).rejects.toThrow('no codec')
    await settle()
    expect(cancel).not.toHaveBeenCalled()
  })

  it('does not cancel the body when the codec resolves', async () => {
    const { response, cancel } = responseWithBody()
    await withCodec(Promise.resolve(codec), Promise.resolve(response))
    await settle()
    expect(cancel).not.toHaveBeenCalled()
  })

  it('surfaces the read error when the codec resolves and the read fails', async () => {
    await expect(
      withCodec(
        Promise.resolve(codec),
        Promise.reject(new Error('read failed'))
      )
    ).rejects.toThrow('read failed')
  })
})
