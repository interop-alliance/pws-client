/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A `ReadableStream<Uint8Array>` written and read through the handle API, end
 * to end over an in-memory PWS server. On an encrypted random-id collection
 * `add(stream)` and a create by `put(stream)` always take the chunked-stream
 * path, whatever the stream's size, and `getStream()` hands the decrypted
 * bytes back as a stream. A write by id over an existing document replaces
 * it through the same path. A content-addressed collection and a plaintext
 * collection refuse a stream with `ValidationError` before reading it.
 */
import { describe, it, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'

import {
  EncryptionError,
  NotFoundError,
  ValidationError
} from '../../src/index.js'
import { blobBytes } from '../../src/edv/core.js'
import { spaceUrlFor } from '../helpers/stubClient.js'
import { bytesOf, drain, flipFirst, streamOf } from '../helpers/bytes.js'
import {
  chunkPaths,
  encryptedCollection,
  memoryServer
} from '../helpers/memoryServer.js'

describe('add(stream) on an encrypted collection', () => {
  it('stores a document plus chunk resources and reads back byte-exact', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(100)

    const added = await collection.add(streamOf({ bytes, pieceSize: 7 }), {
      contentType: 'video/mp4'
    })
    expect(added.contentType).toBe('video/mp4')
    expect(server.store.has(`/space/s/c/${added.id}`)).toBe(true)
    // 100 bytes at a 24-byte chunk size.
    expect(chunkPaths({ server, id: added.id }).length).toBe(5)

    const read = await collection.get(added.id)
    expect(read).toBeInstanceOf(Blob)
    expect((read as Blob).type).toBe('video/mp4')
    expect(await blobBytes(read as Blob)).toEqual(bytes)
  })

  it('chunks a stream under maxBlobBytes too (its size is unknown)', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(8)

    const { id } = await collection.add(streamOf({ bytes, pieceSize: 8 }))
    expect(chunkPaths({ server, id }).length).toBe(1)
    const read = (await collection.get(id)) as Blob
    expect(read.type).toBe('application/octet-stream')
    expect(await blobBytes(read)).toEqual(bytes)
  })

  it("is refused on a content-addressed collection (idDerivation: 'content')", async () => {
    const { server, collection } = await encryptedCollection({
      idDerivation: 'content'
    })
    const stream = streamOf({ bytes: bytesOf(8), pieceSize: 8 })

    await expect(collection.add(stream)).rejects.toBeInstanceOf(ValidationError)
    await expect(
      collection.add(streamOf({ bytes: bytesOf(8), pieceSize: 8 }))
    ).rejects.toThrow(/no known size/)
    expect(stream.locked).toBe(false)
    expect(server.store.size).toBe(0)
  })
})

describe('a chunked write that fails midway', () => {
  it('cancels the caller stream so its source is released', async () => {
    const { server, collection } = await encryptedCollection()
    let cancelled: unknown = undefined
    let pulls = 0
    const source = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++
        controller.enqueue(bytesOf(24))
      },
      cancel(reason) {
        cancelled = reason
      }
    })
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path.endsWith('/chunks/1')

    await expect(collection.add(source)).rejects.toThrow()
    expect(cancelled).toBeInstanceOf(Error)
    expect(pulls).toBeGreaterThan(0)
    // Nothing of this write survives on the server.
    expect(server.store.size).toBe(0)
  })

  it('snapshots a Uint8Array payload, so reusing the buffer mid-write is harmless', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(100)
    const buffer = bytes.slice()
    server.beforeRequest.run = (args, path) => {
      // Scribble over the caller's buffer while the chunks are being written.
      if (args.method === 'PUT' && path.includes('/chunks/')) {
        buffer.fill(0)
      }
    }

    const { id } = await collection.add(buffer)
    server.beforeRequest.run = undefined
    expect(await blobBytes((await collection.get(id)) as Blob)).toEqual(bytes)
  })
})

describe('put(stream) by id on an encrypted collection', () => {
  it('creates the resource at an id that holds no document', async () => {
    const { server, collection } = await encryptedCollection()
    const id = (await EdvClientCore.generateId()) as string
    const bytes = bytesOf(50)

    await collection.put(id, streamOf({ bytes, pieceSize: 11 }), {
      contentType: 'image/png'
    })
    expect(chunkPaths({ server, id }).length).toBe(3)
    const read = (await collection.get(id)) as Blob
    expect(read.type).toBe('image/png')
    expect(await blobBytes(read)).toEqual(bytes)
  })

  it('replaces an existing document, reading the stream as chunks', async () => {
    const { server, collection } = await encryptedCollection()
    const id = (await EdvClientCore.generateId()) as string
    await collection.put(id, { held: true })
    const bytes = bytesOf(50)

    const stream = streamOf({ bytes, pieceSize: 11 })
    await collection.resource(id).put(stream, { contentType: 'image/png' })
    expect(chunkPaths({ server, id }).length).toBe(3)
    const read = (await collection.get(id)) as Blob
    expect(read.type).toBe('image/png')
    expect(await blobBytes(read)).toEqual(bytes)
  })
})

/**
 * Rewrites the JWE of stored chunk 1 of resource `id` in place, through
 * `mutate`, so a read of that chunk meets a corrupted or malformed chunk.
 *
 * @param store {Map<string, Uint8Array>}   the memory server's bodies by path
 * @param id {string}
 * @param mutate {(jwe: Record<string, unknown>) => void}
 */
function rewriteChunk(
  store: Map<string, Uint8Array>,
  id: string,
  mutate: (jwe: Record<string, unknown>) => void
): void {
  const path = `/space/s/c/${id}/chunks/1`
  const chunk = JSON.parse(new TextDecoder().decode(store.get(path))) as {
    jwe: Record<string, unknown>
  }
  mutate(chunk.jwe)
  store.set(path, new TextEncoder().encode(JSON.stringify(chunk)))
}

describe('getStream() on an encrypted collection', () => {
  it('returns the decrypted chunked bytes and the plaintext content type', async () => {
    const { collection } = await encryptedCollection()
    const bytes = bytesOf(100)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 13 }), {
      contentType: 'video/mp4'
    })

    const fromResource = await collection.resource(id).getStream()
    expect(fromResource).not.toBeNull()
    expect(fromResource!.contentType).toBe('video/mp4')
    expect(fromResource!.etag).toMatch(/^"/)
    expect(await drain(fromResource!.stream)).toEqual(bytes)

    const fromCollection = await collection.getStream(id)
    expect(fromCollection!.contentType).toBe('video/mp4')
    expect(await drain(fromCollection!.stream)).toEqual(bytes)
  })

  it('reads chunks as the stream is read, not up front', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(24 * 10)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 24 }))

    let chunkReads = 0
    server.beforeRequest.run = (args, path) => {
      if ((args.method ?? 'GET') === 'GET' && path.includes('/chunks/')) {
        chunkReads++
      }
    }
    const read = await collection.resource(id).getStream()
    expect(chunkReads).toBeLessThan(10)
    expect(await drain(read!.stream)).toEqual(bytes)
    expect(chunkReads).toBe(10)
  })

  it('streams an inline JSON document as UTF-8 JSON', async () => {
    const { collection } = await encryptedCollection()
    const { id } = await collection.add({ hello: 'world' })

    const read = await collection.getStream(id)
    expect(read!.contentType).toBe('application/json')
    expect(new TextDecoder().decode(await drain(read!.stream))).toBe(
      '{"hello":"world"}'
    )
  })

  it('streams an inline binary document with its sealed type', async () => {
    const { collection } = await encryptedCollection()
    const bytes = bytesOf(10)
    const { id } = await collection.add(bytes, { contentType: 'image/gif' })

    const read = await collection.getStream(id)
    expect(read!.contentType).toBe('image/gif')
    expect(await drain(read!.stream)).toEqual(bytes)
  })

  it('resolves null for a missing resource', async () => {
    const { collection } = await encryptedCollection()
    const id = (await EdvClientCore.generateId()) as string
    await expect(collection.getStream(id)).resolves.toBeNull()
  })

  it('errors the stream with a typed NotFoundError when a chunk is missing', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(60)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 20 }))
    server.store.delete(`/space/s/c/${id}/chunks/1`)

    const read = await collection.getStream(id)
    await expect(drain(read!.stream)).rejects.toBeInstanceOf(NotFoundError)
    await expect(collection.get(id)).rejects.toBeInstanceOf(NotFoundError)
  })

  it('errors the stream with a typed EncryptionError when a chunk is tampered with', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(60)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 20 }))
    rewriteChunk(server.store, id, jwe => {
      jwe.ciphertext = flipFirst(jwe.ciphertext as string)
    })

    const read = await collection.getStream(id)
    const streamed = await drain(read!.stream).catch((err: unknown) => err)
    expect(streamed).toBeInstanceOf(EncryptionError)
    expect((streamed as Error).message).toMatch(/failed to decrypt/)
    const buffered = await collection.get(id).catch((err: unknown) => err)
    expect(buffered).toBeInstanceOf(EncryptionError)
    expect((buffered as Error).name).toBe('EncryptionError')
  })

  it('errors the stream with a typed EncryptionError when a chunk is sealed under another key', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(60)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 20 }))
    // A wrapped content key the reader's key does not unwrap: the cipher's
    // key miss, not an AEAD failure
    rewriteChunk(server.store, id, jwe => {
      const recipient = (jwe.recipients as { encrypted_key: string }[])[0]!
      recipient.encrypted_key = recipient.encrypted_key.slice(0, -2)
    })

    const read = await collection.getStream(id)
    const streamed = await drain(read!.stream).catch((err: unknown) => err)
    expect(streamed).toBeInstanceOf(EncryptionError)
    expect((streamed as Error).message).toMatch(/failed to decrypt/)
    expect((streamed as Error).cause).toMatchObject({ name: 'KeyMissError' })
  })

  it('passes an untyped cipher error through unchanged instead of relabeling it', async () => {
    const { server, collection } = await encryptedCollection()
    const bytes = bytesOf(60)
    const { id } = await collection.add(streamOf({ bytes, pieceSize: 20 }))
    // A malformed chunk: the cipher refuses it before any key or AEAD step
    // with a plain Error, which is not tampering and must surface as is
    rewriteChunk(server.store, id, jwe => {
      delete jwe.iv
    })

    const read = await collection.getStream(id)
    const streamed = await drain(read!.stream).catch((err: unknown) => err)
    expect(streamed).toBeInstanceOf(Error)
    expect(streamed).not.toBeInstanceOf(EncryptionError)
    expect((streamed as Error).message).toMatch(/"iv"/)
  })
})

describe('add(stream) on a plaintext collection', () => {
  it('is refused with a ValidationError before anything is sent', async () => {
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .spaceAt(spaceUrlFor('s'))
      .collection('c', { encryption: 'plaintext' })
    const requests: string[] = []
    server.beforeRequest.run = (args, path) => {
      requests.push(`${args.method ?? 'GET'} ${path}`)
    }
    const stream = streamOf({ bytes: bytesOf(8), pieceSize: 8 })

    await expect(collection.add(stream)).rejects.toBeInstanceOf(ValidationError)
    await expect(collection.put('r', stream)).rejects.toThrow(
      /encrypted collection/
    )
    expect(stream.locked).toBe(false)
    expect(requests).toEqual([])
  })
})
