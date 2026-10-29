/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * An in-memory WAS server behind a stub `ZcapClient`, plus a reader's keys
 * and the single-epoch descriptor it is recipient zero of -- for unit tests
 * that drive the encrypted chunked-stream paths end to end through the
 * handle API without a live server.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import { WasClient } from '../../src/index.js'
import type { Collection, CollectionEncryption } from '../../src/index.js'
import { createEdvEncryption, ownerRecipient } from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import {
  serviceDescriptionFor,
  baseServerUrlFor,
  spaceUrlFor
} from './stubClient.js'
import type { RequestArgs } from './stubClient.js'

/**
 * A reader's keys and the single-epoch descriptor it is recipient zero of.
 *
 * @returns {Promise<object>}
 */
export async function readerWithDescriptor(): Promise<{
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  encryption: CollectionEncryption
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyAgreementKey = kak as unknown as IKeyAgreementKey
  const keyResolver = (async () => ({
    id: kak.id,
    type: kak.type,
    publicKeyMultibase: kak.publicKeyMultibase
  })) as unknown as IKeyResolver
  const { epochId, secret } = await mintEpoch()
  const recipient = await wrapEpochSecret({
    epochSecret: secret,
    recipient: ownerRecipient({ keyAgreementKey })
  })
  return {
    keys: { keyAgreementKey, keyResolver },
    encryption: {
      scheme: 'edv',
      epochs: [{ id: epochId, recipients: [recipient] }],
      currentEpoch: epochId
    }
  }
}

/**
 * An in-memory WAS server behind a stub `ZcapClient`: `PUT` stores the body
 * under a fresh `ETag` (refusing an `If-None-Match: *` create over a stored
 * path, or an `If-Match` on a stale `ETag`, with 412), `GET` serves it back
 * (404 when absent), and `DELETE` removes a resource together with every
 * chunk stored under it (honoring `If-Match` too). A `GET` of a resource's
 * `chunks/` container lists its stored chunks, each with its `etag`, and a
 * `DELETE` of one chunk removes that chunk alone (404 when absent, before any
 * `If-Match` is looked at, as the server does). `failWhen` makes a chosen
 * request fail with its
 * `status` (default 503), to tear a write, and `beforeRequest` lets a test
 * act as a concurrent writer.
 *
 * @returns {object}   the client, the stored bodies by path, and the hooks
 */
export function memoryServer(): {
  store: Map<string, Uint8Array>
  write: (path: string, body: Uint8Array) => string
  client: (options: {
    maxBlobBytes: number
    chunkSize: number
    idDerivation?: 'random' | 'content'
  }) => WasClient
  failWhen: {
    test?: (args: RequestArgs, path: string) => boolean
    status?: number
  }
  beforeRequest: { run?: (args: RequestArgs, path: string) => void }
} {
  const store = new Map<string, Uint8Array>()
  const etags = new Map<string, string>()
  let version = 0
  const write = (path: string, body: Uint8Array): string => {
    const etag = `"${++version}"`
    store.set(path, body)
    etags.set(path, etag)
    return etag
  }
  const failWhen: {
    test?: (args: RequestArgs, path: string) => boolean
    status?: number
  } = {}
  const beforeRequest: { run?: (args: RequestArgs, path: string) => void } = {}
  const fail = (status: number): never => {
    throw { status, response: { status } }
  }
  const request = async (args: RequestArgs): Promise<HttpResponse> => {
    const path = new URL(args.url!).pathname
    const method = args.method ?? 'GET'
    beforeRequest.run?.(args, path)
    if (failWhen.test?.(args, path)) {
      fail(failWhen.status ?? 503)
    }
    // A chunk delete is not idempotent: an absent chunk is a 404, whatever
    // `If-Match` says.
    if (method === 'DELETE' && path.includes('/chunks/') && !store.has(path)) {
      fail(404)
    }
    const ifMatch = args.headers?.['if-match']
    if (ifMatch !== undefined && etags.get(path) !== ifMatch) {
      fail(412)
    }
    if (method === 'PUT') {
      if (args.headers?.['if-none-match'] === '*' && store.has(path)) {
        fail(412)
      }
      const body =
        args.body instanceof Uint8Array
          ? args.body
          : new TextEncoder().encode(JSON.stringify(args.json))
      const etag = write(path, body)
      return {
        status: 204,
        headers: new Headers({ etag })
      } as unknown as HttpResponse
    }
    if (method === 'DELETE') {
      for (const stored of [...store.keys()]) {
        if (stored === path || stored.startsWith(`${path}/chunks/`)) {
          store.delete(stored)
          etags.delete(stored)
        }
      }
      return { status: 204, headers: new Headers() } as unknown as HttpResponse
    }
    if (path.endsWith('/chunks/')) {
      const resourcePath = path.slice(0, -'/chunks/'.length)
      if (!store.has(resourcePath)) {
        fail(404)
      }
      const chunks = [...store.entries()]
        .filter(([stored]) => stored.startsWith(path))
        .map(([stored, body]) => ({
          index: Number(stored.slice(path.length)),
          size: body.length,
          contentType: 'application/octet-stream',
          etag: etags.get(stored)!
        }))
        .sort((left, right) => left.index - right.index)
      const listing = { count: chunks.length, chunks }
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        data: listing,
        async json() {
          return listing
        }
      } as unknown as HttpResponse
    }
    const bytes = store.get(path)
    if (bytes === undefined) {
      fail(404)
    }
    const text = new TextDecoder().decode(bytes)
    const isChunk = path.includes('/chunks/')
    return {
      status: 200,
      headers: new Headers({
        'content-type': isChunk
          ? 'application/octet-stream'
          : 'application/jose+json',
        etag: etags.get(path)!
      }),
      ...(!isChunk && { data: JSON.parse(text) }),
      async json() {
        return JSON.parse(text)
      },
      async text() {
        return text
      },
      async arrayBuffer() {
        return bytes!.slice().buffer
      }
    } as unknown as HttpResponse
  }
  const client = ({
    maxBlobBytes,
    chunkSize,
    idDerivation
  }: {
    maxBlobBytes: number
    chunkSize: number
    idDerivation?: 'random' | 'content'
  }): WasClient =>
    new WasClient({
      baseServerUrl: baseServerUrlFor(),
      serviceDescription: serviceDescriptionFor(),
      zcapClient: {
        invocationSigner: { id: 'did:example:alice#key-1' },
        request
      } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient'],
      encryption: createEdvEncryption({
        resolveKeys: async () => null,
        maxBlobBytes,
        chunkSize,
        ...(idDerivation !== undefined && { idDerivation })
      })
    })
  return { store, write, client, failWhen, beforeRequest }
}

/**
 * An encrypted collection over a fresh in-memory server, with the routing
 * threshold and chunk size set low (16 and 24 bytes) so a modest payload
 * spans several chunks.
 *
 * @param [options] {object}
 * @param [options.idDerivation] {'random' | 'content'}
 * @returns {Promise<object>}   the server, the collection handle, and the
 *   reader's keys and descriptor the collection is bound to
 */
export async function encryptedCollection({
  idDerivation
}: { idDerivation?: 'random' | 'content' } = {}): Promise<
  Awaited<ReturnType<typeof readerWithDescriptor>> & {
    server: ReturnType<typeof memoryServer>
    collection: Collection
  }
> {
  const { keys, encryption } = await readerWithDescriptor()
  const server = memoryServer()
  const collection = server
    .client({ maxBlobBytes: 16, chunkSize: 24, idDerivation })
    .spaceAt(spaceUrlFor('s'))
    .collection('c', { encryption: { ...encryption, keys } })
  return { server, collection, keys, encryption }
}

/**
 * The chunk resource paths stored under document `id` of the collection
 * {@link encryptedCollection} builds, in index order.
 *
 * @param options {object}
 * @param options.server {object}
 * @param options.id {string}
 * @returns {string[]}
 */
export function chunkPaths({
  server,
  id
}: {
  server: ReturnType<typeof memoryServer>
  id: string
}): string[] {
  return [...server.store.keys()]
    .filter(path => path.startsWith(`/space/s/c/${id}/chunks/`))
    .sort()
}
