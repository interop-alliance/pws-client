/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `collection.add(bigBlob)` auto-routing, end to end against
 * a live WAS server whose backend advertises the `chunked-streams` feature. A
 * binary payload over the codec's `maxBlobBytes` threshold is written as one
 * EDV document plus its chunk resources, and the ordinary `get()` handle reads
 * it back byte-exact -- no `EdvClientCore` or `WasTransport` in the caller's
 * code. A `ReadableStream` payload takes the same path whatever its size, and
 * `getStream()` reads it back as a stream. The threshold is set small here so
 * the blob need not exceed the 512 KiB default.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'

import type { Space, Collection, WasClient } from '../../src/index.js'
import { bytesOf, drain } from '../helpers/bytes.js'
import {
  chunkedClient,
  chunkStatus,
  provisionVault
} from '../helpers/chunkedVault.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

/**
 * The routing threshold and chunk size these tests provision the codec with,
 * both far below the defaults so a modest blob exercises the multi-chunk path.
 */
const MAX_BLOB_BYTES = 4 * 1024
const CHUNK_SIZE = 8 * 1024

describeLive('collection.add(bigBlob) auto-routing (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    const client = await chunkedClient({
      baseServerUrl: baseServerUrl!,
      maxBlobBytes: MAX_BLOB_BYTES,
      chunkSize: CHUNK_SIZE
    })
    was = client.was
    ;({ space, collection } = await provisionVault({
      was,
      kak: client.kak,
      name: 'EDV Chunked Add Integration'
    }))
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('routes a blob over the threshold to chunks and reads it back byte-exact', async () => {
    const bytes = bytesOf(MAX_BLOB_BYTES * 5 + 123)
    const added = await collection.add(bytes, {
      contentType: 'application/octet-stream'
    })
    expect(added.id).toMatch(/^z/)
    expect(added.contentType).toBe('application/octet-stream')

    const read = await collection.get(added.id)
    expect(read).toBeInstanceOf(Blob)
    const out = new Uint8Array(await (read as Blob).arrayBuffer())
    expect(out.length).toBe(bytes.length)
    expect(out).toEqual(bytes)

    // The blob spans several `CHUNK_SIZE` chunks, so the document carries
    // chunk resources on the server. A single-document write stores none.
    await expect(
      chunkStatus({
        was,
        spaceUrl: space.url,
        resourceId: added.id,
        chunkIndex: 0
      })
    ).resolves.toBe(200)
    await expect(
      chunkStatus({
        was,
        spaceUrl: space.url,
        resourceId: added.id,
        chunkIndex: 1
      })
    ).resolves.toBe(200)
  })

  it('writes a stream as chunks and reads it back through get() and getStream()', async () => {
    const bytes = bytesOf(CHUNK_SIZE * 2 + 321)
    const stream = new Blob([bytes as BlobPart]).stream()
    const added = await collection.add(stream, { contentType: 'video/mp4' })
    expect(added.contentType).toBe('video/mp4')

    const read = await collection.get(added.id)
    expect((read as Blob).type).toBe('video/mp4')
    expect(new Uint8Array(await (read as Blob).arrayBuffer())).toEqual(bytes)

    const streamed = await collection.getStream(added.id)
    expect(streamed?.contentType).toBe('video/mp4')
    expect(await drain(streamed!.stream)).toEqual(bytes)

    await expect(
      chunkStatus({
        was,
        spaceUrl: space.url,
        resourceId: added.id,
        chunkIndex: 2
      })
    ).resolves.toBe(200)
  })

  it('keeps a blob under the threshold on the single-document path', async () => {
    const bytes = bytesOf(MAX_BLOB_BYTES - 1)
    const { id } = await collection.add(bytes, {
      contentType: 'application/octet-stream'
    })
    const read = await collection.get(id)
    expect(new Uint8Array(await (read as Blob).arrayBuffer())).toEqual(bytes)

    // Sealed into one document: no chunk resource exists under it.
    await expect(
      chunkStatus({ was, spaceUrl: space.url, resourceId: id, chunkIndex: 0 })
    ).resolves.toBe(404)
  })
})
