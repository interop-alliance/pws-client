/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Tests for the portable `Blob` read helpers (`src/internal/blob.ts`): the
 * native `text()` / `arrayBuffer()` path taken in a browser and in Node, and
 * the `FileReader` fallback taken on React Native, whose `Blob` implements
 * neither method. Node has no global `FileReader`, so the fallback tests
 * install a stub for the duration and restore the global afterward. Also the
 * write direction: `bytesToBlob` (the constructor, and the `data:` URL
 * fallback for a `Blob` constructor that refuses bytes) and `streamToBlob`
 * (a drain that keeps the stream's own error).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  blobBytes,
  blobText,
  bytesToBlob,
  streamToBlob
} from '../../src/internal/blob.js'
import { NotFoundError } from '../../src/index.js'
import { installFileReader, rnBlob } from '../helpers/rnBlob.js'

let restore: (() => void) | undefined

afterEach(() => {
  restore?.()
  restore = undefined
})

describe('blobText / blobBytes: React Native shape (no native methods)', () => {
  it('reads text through the FileReader fallback', async () => {
    restore = installFileReader()
    const blob = rnBlob(['{"a":1}\n{"a":2}\n'], { type: 'text/jsonl' })
    expect(blob.text).toBeUndefined()
    expect(await blobText(blob)).toBe('{"a":1}\n{"a":2}\n')
  })

  it('reads bytes through the FileReader fallback', async () => {
    restore = installFileReader()
    const bytes = new Uint8Array([137, 80, 78, 71, 0, 255])
    const blob = rnBlob([bytes], { type: 'image/png' })
    expect(blob.arrayBuffer).toBeUndefined()
    expect(await blobBytes(blob)).toEqual(bytes)
  })

  it('rejects when the reader fires onerror', async () => {
    restore = installFileReader({ fail: true })
    const blob = rnBlob(['hello'])
    await expect(blobText(blob)).rejects.toThrow('stub FileReader failure')
    await expect(blobBytes(blob)).rejects.toThrow('stub FileReader failure')
  })

  it('throws when there is no native method and no FileReader either', async () => {
    const blob = rnBlob(['hello'])
    await expect(blobText(blob)).rejects.toBeInstanceOf(TypeError)
    await expect(blobBytes(blob)).rejects.toBeInstanceOf(TypeError)
  })
})

describe('blobText / blobBytes: native shape', () => {
  it('reads a complete Blob with no FileReader global present', async () => {
    expect((globalThis as { FileReader?: unknown }).FileReader).toBeUndefined()
    const bytes = new Uint8Array([1, 2, 3, 4])
    expect(await blobText(new Blob(['plain text']))).toBe('plain text')
    expect(await blobBytes(new Blob([bytes]))).toEqual(bytes)
  })
})

describe('streamToBlob', () => {
  it('concatenates the chunks, in order, typed as given', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]))
        controller.enqueue(new Uint8Array([3]))
        controller.close()
      }
    })
    const blob = await streamToBlob({ stream, type: 'image/png' })
    expect(blob.type).toBe('image/png')
    expect(await blobBytes(blob)).toEqual(new Uint8Array([1, 2, 3]))
  })

  it("rejects with the stream's own error", async () => {
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array([1]))
        controller.error(new NotFoundError('chunk 1 is missing'))
      }
    })
    const failure = await streamToBlob({ stream }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotFoundError)
    expect((failure as Error).message).toBe('chunk 1 is missing')
  })

  it('rejects a chunk that is not bytes instead of stringifying it', async () => {
    const stream = new ReadableStream<unknown>({
      start(controller) {
        controller.enqueue({ not: 'bytes' })
        controller.close()
      }
    }) as ReadableStream<Uint8Array>
    await expect(streamToBlob({ stream })).rejects.toBeInstanceOf(TypeError)
  })

  it('cancels the stream before rejecting on a chunk that is not bytes', async () => {
    const cancel = vi.fn()
    const stream = new ReadableStream<unknown>({
      start(controller) {
        controller.enqueue({ not: 'bytes' })
      },
      cancel
    }) as ReadableStream<Uint8Array>
    const failure = await streamToBlob({ stream }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(TypeError)
    expect(cancel).toHaveBeenCalledWith(failure)
  })
})

describe('bytesToBlob: a Blob constructor that refuses bytes (React Native)', () => {
  const NativeBlob = globalThis.Blob
  class RnBlob extends NativeBlob {
    constructor(parts?: BlobPart[], options?: BlobPropertyBag) {
      if (parts?.some(part => ArrayBuffer.isView(part))) {
        throw new TypeError(
          'Creating blobs from ArrayBuffer and ArrayBufferView are not ' +
            'supported'
        )
      }
      super(parts, options)
    }
  }

  afterEach(() => {
    globalThis.Blob = NativeBlob
    vi.unstubAllGlobals()
  })

  it('fetches the bytes back as a Blob from a data: URL', async () => {
    globalThis.Blob = RnBlob
    const fetched: string[] = []
    vi.stubGlobal('fetch', async (url: string) => {
      fetched.push(url)
      const [header, payload] = url.slice('data:'.length).split(',')
      const type = header!.replace(/;base64$/, '')
      const bytes = Uint8Array.from(atob(payload!), char => char.charCodeAt(0))
      // The fallback's own Blob is built from a string, which RN accepts.
      return {
        blob: async () =>
          new NativeBlob([String.fromCharCode(...bytes)], { type })
      }
    })
    const blob = await bytesToBlob({
      parts: [new Uint8Array([104, 105]), new Uint8Array([33])],
      type: 'text/plain'
    })
    expect(fetched).toEqual(['data:application/octet-stream;base64,aGkh'])
    expect(blob.type).toBe('text/plain')
    expect(await blobText(blob)).toBe('hi!')
  })

  it('keeps a type with parameters out of the data: URL and on the Blob', async () => {
    globalThis.Blob = RnBlob
    const fetched: string[] = []
    vi.stubGlobal('fetch', async (url: string) => {
      fetched.push(url)
      return { blob: async () => new NativeBlob(['hi!']) }
    })
    const blob = await bytesToBlob({
      parts: [new Uint8Array([104, 105, 33])],
      type: 'text/plain; charset=utf-8'
    })
    expect(fetched).toEqual(['data:application/octet-stream;base64,aGkh'])
    expect(blob.type).toBe('text/plain; charset=utf-8')
    expect(await blobText(blob)).toBe('hi!')
  })
})
