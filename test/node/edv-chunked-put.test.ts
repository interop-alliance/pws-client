/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A large encrypted binary written by id through the handle API, end to end
 * over an in-memory PWS server: `resource.put()` on a random-id encrypted
 * handle routes an over-threshold payload to the chunked write at the
 * caller's id, a second create-if-absent `put()` at that id fails with a 412
 * so the caller can read the held copy, and a pending stub left by a torn
 * write is recognized with the doc cipher's `isPendingStub` and removed with
 * `resource.delete()`, which takes its chunks with it.
 *
 * The second half covers the replace case: a `put()` over a stored document,
 * in every combination of inline and chunked prior and payload. A chunked
 * prior document has the chunks the new document does not cover reaped after
 * the write, a torn replace leaves a pending stub for the next write to
 * replace, and a stale baseline fails before anything is written.
 */
import { describe, it, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'

import {
  ConflictError,
  EncryptionError,
  PreconditionFailedError
} from '../../src/index.js'
import type { Json } from '../../src/index.js'
import {
  createEdvDocCipher,
  createRefreshingEdvDocCipher
} from '../../src/edv/index.js'
import { blobBytes } from '../../src/edv/core.js'
import { bytesOf } from '../helpers/bytes.js'
import {
  chunkPaths,
  encryptedCollection,
  memoryServer
} from '../helpers/memoryServer.js'
import type { RequestArgs } from '../helpers/stubClient.js'

/**
 * {@link encryptedCollection} plus a fresh random document id to write at.
 *
 * @returns {Promise<object>}   the server, the collection, and the id
 */
async function fixture(): Promise<
  Awaited<ReturnType<typeof encryptedCollection>> & { id: string }
> {
  const id = (await EdvClientCore.generateId()) as string
  return { ...(await encryptedCollection()), id }
}

/**
 * Records every request the server sees, from the moment it is installed.
 *
 * @param server {ReturnType<typeof memoryServer>}
 * @returns {Array<{ method: string; path: string; headers?: object }>}
 */
function recordRequests(
  server: ReturnType<typeof memoryServer>
): Array<{ method: string; path: string; headers?: RequestArgs['headers'] }> {
  const seen: Array<{
    method: string
    path: string
    headers?: RequestArgs['headers']
  }> = []
  server.beforeRequest.run = (args, path) => {
    seen.push({ method: args.method ?? 'GET', path, headers: args.headers })
  }
  return seen
}

describe('Resource.put: a chunked encrypted write by id', () => {
  const blob = bytesOf(64)

  it('round-trips at the caller id, and a second create-if-absent put gets a 412', async () => {
    const { server, collection, id } = await fixture()
    const resource = collection.resource(id)

    await resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    expect(chunkPaths({ server, id }).length).toBe(3)

    const held = await resource.get()
    expect(held).toBeInstanceOf(Blob)
    expect((held as Blob).type).toBe('image/png')
    expect(await blobBytes(held as Blob)).toEqual(blob)

    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
  })

  it('leaves a pending stub the caller can recognize and delete, then rewrite', async () => {
    const { server, collection, keys, encryption, id } = await fixture()
    const resource = collection.resource(id)
    const documentPath = `/space/s/c/${id}`

    // Tear the write after the first document write: the second chunk and
    // the cleanup delete both fail, so the stub stays with one chunk.
    server.failWhen.test = (args, path) =>
      (args.method === 'PUT' && path.endsWith('/chunks/1')) ||
      args.method === 'DELETE'
    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(EncryptionError)
    server.failWhen.test = undefined
    expect(server.store.has(documentPath)).toBe(true)

    // The next run: the id is taken, and the held copy cannot be read.
    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    await expect(resource.get()).rejects.toBeInstanceOf(EncryptionError)

    // The caller recognizes the stub from its raw envelope...
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    const envelope = (await collection
      .resource(id, { encryption: 'plaintext' })
      .get()) as Json
    await expect(cipher.isPendingStub({ id, envelope })).resolves.toBe(true)
    // ...through the self-refreshing cipher a sync engine holds, too.
    const refreshing = await createRefreshingEdvDocCipher({
      ...keys,
      collectionId: 'c',
      cache: {
        readDescriptor: async () => encryption,
        writeDescriptor: async () => {}
      }
    })
    await expect(refreshing.isPendingStub({ id, envelope })).resolves.toBe(true)

    // ...deletes it, chunks included, and writes the Resource again.
    await resource.delete()
    expect(
      [...server.store.keys()].some(path => path.startsWith(documentPath))
    ).toBe(false)
    await resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    expect(await blobBytes((await resource.get()) as Blob)).toEqual(blob)
  })

  it('fails with a 412 and keeps the document another writer stored mid-write', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`
    const theirs = new TextEncoder().encode('{"theirs":true}')

    // Another writer replaces the pending stub just before the final update.
    let documentPuts = 0
    server.beforeRequest.run = (args, path) => {
      if (args.method === 'PUT' && path === documentPath) {
        documentPuts++
        if (documentPuts === 2) {
          server.write(documentPath, theirs)
        }
      }
    }
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(server.store.get(documentPath)).toEqual(theirs)
  })

  it('surfaces a 409 on the first document write as a ConflictError', async () => {
    const { server, collection, id } = await fixture()

    server.failWhen.status = 409
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path === `/space/s/c/${id}`
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(ConflictError)
  })

  it('surfaces a 409 on the final update as a ConflictError and deletes the stub', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`

    let documentPuts = 0
    server.failWhen.status = 409
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path === documentPath && ++documentPuts === 2
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(ConflictError)
    expect(
      [...server.store.keys()].some(path => path.startsWith(documentPath))
    ).toBe(false)
  })
})

describe('Resource.put: replacing a stored encrypted document', () => {
  const big = bytesOf(64)
  const smaller = bytesOf(30)

  it('replaces an inline document with a chunked one', async () => {
    const { server, collection, id } = await fixture()
    await collection.put(id, { held: true })

    const seen = recordRequests(server)
    const { etag } = await collection
      .resource(id)
      .put(big, { contentType: 'image/png' })
    expect(etag).toBeDefined()
    expect(chunkPaths({ server, id }).length).toBe(3)
    const read = (await collection.get(id)) as Blob
    expect(read.type).toBe('image/png')
    expect(await blobBytes(read)).toEqual(big)
    // The prior document held no chunks, so nothing was listed or reaped.
    expect(seen.some(request => request.path.endsWith('/chunks/'))).toBe(false)
    expect(seen.some(request => request.method === 'DELETE')).toBe(false)
  })

  it('shrinks a chunked document and reaps the chunks beyond the new count', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`
    const { etag } = await collection.put(id, big, { contentType: 'image/png' })
    expect(chunkPaths({ server, id }).length).toBe(3)

    const seen = recordRequests(server)
    await collection.resource(id).put(smaller, { contentType: 'image/png' })
    expect(chunkPaths({ server, id })).toEqual([
      `${documentPath}/chunks/0`,
      `${documentPath}/chunks/1`
    ])
    expect(await blobBytes((await collection.get(id)) as Blob)).toEqual(smaller)
    // The first document write was pinned to the pre-read, the stale chunk
    // was listed and then deleted under the `etag` the listing reported (the
    // memory server's validators are quoted integers).
    const documentPuts = seen.filter(
      request => request.method === 'PUT' && request.path === documentPath
    )
    expect(documentPuts[0]!.headers?.['if-match']).toBe(etag)
    const deletes = seen.filter(request => request.method === 'DELETE')
    expect(deletes.map(request => request.path)).toEqual([
      `${documentPath}/chunks/2`
    ])
    expect(deletes[0]!.headers?.['if-match']).toMatch(/^"\d+"$/)
  })

  it('replaces a chunked document with an inline one and reaps every chunk', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`
    const { etag } = await collection.put(id, big, { contentType: 'image/png' })

    const seen = recordRequests(server)
    await collection.resource(id).put({ small: true })
    expect(chunkPaths({ server, id })).toEqual([])
    expect(await collection.get(id)).toEqual({ small: true })
    const documentPut = seen.find(
      request => request.method === 'PUT' && request.path === documentPath
    )
    expect(documentPut?.headers?.['if-match']).toBe(etag)
  })

  it('lists no chunks for an inline document replaced by an inline one', async () => {
    const { server, collection, id } = await fixture()
    await collection.put(id, { v: 1 })
    const seen = recordRequests(server)
    await collection.resource(id).put({ v: 2 })
    expect(seen.map(request => request.method)).toEqual(['GET', 'PUT'])
    expect(await collection.get(id)).toEqual({ v: 2 })
  })

  it('rewrites a pending stub, reaping the chunks it left', async () => {
    const { server, collection, id } = await fixture()
    server.failWhen.test = (args, path) =>
      (args.method === 'PUT' && path.endsWith('/chunks/1')) ||
      args.method === 'DELETE'
    await expect(
      collection.put(id, big, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(EncryptionError)
    server.failWhen.test = undefined
    expect(chunkPaths({ server, id }).length).toBe(1)

    await collection.resource(id).put({ recovered: true })
    expect(chunkPaths({ server, id })).toEqual([])
    expect(await collection.get(id)).toEqual({ recovered: true })
  })

  it('leaves the pending stub in place when a replace tears, for the next write', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`
    await collection.put(id, big, { contentType: 'image/png' })

    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path.endsWith('/chunks/1')
    const failure = await collection
      .resource(id)
      .put(smaller, { contentType: 'image/png' })
      .catch((err: unknown) => err)
    server.failWhen.test = undefined
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/pending stub/)
    // The resource was not deleted: the stub stands where the document was.
    expect(server.store.has(documentPath)).toBe(true)
    await expect(collection.get(id)).rejects.toBeInstanceOf(EncryptionError)

    // The next write at the id replaces the stub and reaps its chunks.
    await collection.resource(id).put(smaller, { contentType: 'image/png' })
    expect(chunkPaths({ server, id }).length).toBe(2)
    expect(await blobBytes((await collection.get(id)) as Blob)).toEqual(smaller)
  })

  it('fails with a 412 and writes nothing when the document moved after the pre-read', async () => {
    const { server, collection, id } = await fixture()
    const documentPath = `/space/s/c/${id}`
    await collection.put(id, { v: 1 })
    const theirs = new TextEncoder().encode('{"theirs":true}')

    // Another writer stores a new version just before this write's first PUT.
    server.beforeRequest.run = (args, path) => {
      if (args.method === 'PUT' && path === documentPath) {
        server.beforeRequest.run = undefined
        server.write(documentPath, theirs)
      }
    }
    await expect(
      collection.resource(id).put(big, { contentType: 'image/png' })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(server.store.get(documentPath)).toEqual(theirs)
    expect(chunkPaths({ server, id })).toEqual([])
  })

  it('refuses a stale caller baseline before the pre-read is written over', async () => {
    const { server, collection, id } = await fixture()
    const { etag } = await collection.put(id, big, { contentType: 'image/png' })

    await expect(
      collection.resource(id).put({ small: true }, { ifMatch: '"stale"' })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(chunkPaths({ server, id }).length).toBe(3)

    await collection.resource(id).put({ small: true }, { ifMatch: etag })
    expect(chunkPaths({ server, id })).toEqual([])
    expect(await collection.get(id)).toEqual({ small: true })
  })

  it('reports a failed reap after the document is stored', async () => {
    const { server, collection, id } = await fixture()
    await collection.put(id, big, { contentType: 'image/png' })

    server.failWhen.test = args => args.method === 'DELETE'
    const failure = await collection
      .resource(id)
      .put({ small: true })
      .catch((err: unknown) => err)
    server.failWhen.test = undefined
    expect(failure).toBeInstanceOf(EncryptionError)
    expect((failure as Error).message).toMatch(/is stored/)
    // The write landed; only the stale chunks remain, until the resource is
    // deleted.
    expect(await collection.get(id)).toEqual({ small: true })
    expect(chunkPaths({ server, id }).length).toBe(3)
    await collection.resource(id).delete()
    expect(chunkPaths({ server, id })).toEqual([])
  })

  it('treats a chunk already gone, or replaced since it was listed, as reaped', async () => {
    const { server, collection, id } = await fixture()
    await collection.put(id, big, { contentType: 'image/png' })

    server.failWhen.status = 404
    server.failWhen.test = (args, path) =>
      args.method === 'DELETE' && path.endsWith('/chunks/1')
    await collection.resource(id).put({ small: true })
    server.failWhen.status = 412
    server.failWhen.test = (args, path) =>
      args.method === 'DELETE' && path.endsWith('/chunks/2')
    await collection.resource(id).put({ small: true, again: true })
    expect(await collection.get(id)).toEqual({ small: true, again: true })
  })

  it('treats a resource deleted before the reap as nothing to reap', async () => {
    const { server, collection, id } = await fixture()
    await collection.put(id, big, { contentType: 'image/png' })

    // Another client deletes the resource (and its chunks with it) between
    // the document write and the chunk listing.
    server.beforeRequest.run = (args, path) => {
      if (args.method === 'GET' && path.endsWith('/chunks/')) {
        server.beforeRequest.run = undefined
        for (const stored of [...server.store.keys()]) {
          if (stored.includes(`/${id}`)) {
            server.store.delete(stored)
          }
        }
      }
    }
    await expect(
      collection.resource(id).put({ small: true })
    ).resolves.toBeDefined()
    expect(chunkPaths({ server, id })).toEqual([])
  })
})
