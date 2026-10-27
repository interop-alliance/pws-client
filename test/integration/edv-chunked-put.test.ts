/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `resource.put()` over a stored encrypted document, end to
 * end against a live WAS server. A chunked document replaced by a shorter one
 * keeps only the chunks the new document covers, one replaced by an inline
 * document keeps none, and an inline document replaced by a large blob gains
 * chunks -- each read back byte-exact through the ordinary `get()`, with the
 * chunk set observed straight off the server.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'

import type { Space, Collection, WasClient } from '../../src/index.js'
import { bytesOf } from '../helpers/bytes.js'
import {
  chunkedClient,
  chunkStatus,
  provisionVault
} from '../helpers/chunkedVault.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * The routing threshold and chunk size these tests provision the codec with,
 * both far below the defaults so a modest blob exercises the multi-chunk path.
 */
const MAX_BLOB_BYTES = 4 * 1024
const CHUNK_SIZE = 8 * 1024

describeLive('resource.put() over a stored document (live server)', () => {
  let was: WasClient
  let space: Space
  let collection: Collection

  beforeAll(async () => {
    const client = await chunkedClient({
      serverUrl: serverUrl!,
      maxBlobBytes: MAX_BLOB_BYTES,
      chunkSize: CHUNK_SIZE
    })
    was = client.was
    ;({ space, collection } = await provisionVault({
      was,
      kak: client.kak,
      name: 'EDV Chunked Put Integration'
    }))
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  /**
   * The status of chunk `chunkIndex` of `resourceId` on the server.
   *
   * @param resourceId {string}
   * @param chunkIndex {number}
   * @returns {Promise<number | undefined>}
   */
  function chunk(resourceId: string, chunkIndex: number) {
    return chunkStatus({ was, spaceId: space.id, resourceId, chunkIndex })
  }

  it('shrinks a chunked document and reaps the chunks beyond the new count', async () => {
    const id = (await EdvClientCore.generateId()) as string
    const resource = collection.resource(id)
    await resource.put(bytesOf(CHUNK_SIZE * 4 + 5), {
      contentType: 'application/octet-stream'
    })
    await expect(chunk(id, 4)).resolves.toBe(200)

    const shorter = bytesOf(CHUNK_SIZE + 7)
    const { etag } = await resource.put(shorter, {
      contentType: 'application/octet-stream'
    })
    expect(etag).toBeDefined()
    const read = (await resource.get()) as Blob
    expect(new Uint8Array(await read.arrayBuffer())).toEqual(shorter)

    await expect(chunk(id, 0)).resolves.toBe(200)
    await expect(chunk(id, 1)).resolves.toBe(200)
    await expect(chunk(id, 2)).resolves.toBe(404)
    await expect(chunk(id, 4)).resolves.toBe(404)
  })

  it('replaces a chunked document with an inline one and reaps every chunk', async () => {
    const id = (await EdvClientCore.generateId()) as string
    const resource = collection.resource(id)
    await resource.put(bytesOf(CHUNK_SIZE * 2 + 1), {
      contentType: 'application/octet-stream'
    })
    await expect(chunk(id, 2)).resolves.toBe(200)

    await resource.put({ inline: true })
    expect(await resource.get()).toEqual({ inline: true })
    await expect(chunk(id, 0)).resolves.toBe(404)
    await expect(chunk(id, 2)).resolves.toBe(404)
  })

  it('replaces an inline document with a chunked one', async () => {
    const id = (await EdvClientCore.generateId()) as string
    const resource = collection.resource(id)
    await resource.put({ inline: true })
    await expect(chunk(id, 0)).resolves.toBe(404)

    const bytes = bytesOf(CHUNK_SIZE * 2 + 9)
    await resource.put(bytes, { contentType: 'image/png' })
    const read = (await resource.get()) as Blob
    expect(read.type).toBe('image/png')
    expect(new Uint8Array(await read.arrayBuffer())).toEqual(bytes)
    await expect(chunk(id, 2)).resolves.toBe(200)
  })
})
