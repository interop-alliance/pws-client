/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: chunked encrypted blobs over PWS, end to end, against a
 * live PWS server whose backend advertises the `chunked-streams` feature.
 * Proves two things:
 *
 * 1. Transport-level `PwsTransport.storeChunk` / `getChunk` round-trip an
 *    opaque EDV chunk object through the reserved `.../chunks/{n}` sub-segment.
 * 2. A blob larger than one chunk, driven through
 *    `EdvClientCore.insert({ stream })` and read back with `getStream`,
 *    encrypts client-side, stores as N opaque chunks over PWS, and decrypts
 *    byte-for-byte -- reusing minimal-cipher's proven encrypt/decrypt with no
 *    server change (the server stores ciphertext fragments it never parses).
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { EdvClientCore } from '@interop/edv-client'
import type { IEDVChunk, IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { PwsClient } from '../../src/index.js'
import type { Space, Collection } from '../../src/index.js'
import { PwsTransport } from '../../src/edv/index.js'
import { drain, streamOf } from '../helpers/bytes.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

/**
 * Builds a fresh did:key Ed25519 signer and a PWS client over it.
 *
 * @returns {Promise<PwsClient>}
 */
async function freshPwsClient(): Promise<PwsClient> {
  const keyPair = await Ed25519VerificationKey.generate()
  return PwsClient.fromSigner({
    baseServerUrl: baseServerUrl!,
    signer: keyPair.didKeySigner()
  })
}

describeLive('chunked encrypted blobs over PWS (live server)', () => {
  let pws: PwsClient
  let space: Space
  let collection: Collection
  let edv: EdvClientCore
  let transport: PwsTransport

  beforeAll(async () => {
    pws = await freshPwsClient()
    space = await pws.createSpace({ name: 'EDV Chunk Integration' })
    collection = await space.createCollection({ id: 'vault', name: 'Vault' })

    const kak = await X25519KeyAgreementKey2020.generate({
      controller: pws.controllerDid
    })
    const keyResolver = async ({ id }: { id?: string }) => {
      if (id !== kak.id) {
        throw new Error(`Unknown key id "${id}".`)
      }
      return {
        id: kak.id,
        type: kak.type,
        publicKeyMultibase: kak.publicKeyMultibase
      }
    }
    edv = new EdvClientCore({
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver
    })
    transport = new PwsTransport({
      pws,
      spaceUrl: space.url,
      collectionId: collection.id
    })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('round-trips an opaque EDV chunk via storeChunk/getChunk', async () => {
    // The parent Resource must exist before its chunks (the server rejects an
    // orphan chunk with 404), so create a document first.
    const inserted = await edv.insert({
      doc: { content: { note: 'parent of a hand-written chunk' } },
      transport
    })

    const chunk = {
      sequence: 0,
      index: 0,
      offset: 0,
      // The server stores the chunk opaquely, so any JSON `jwe` round-trips.
      jwe: {
        protected: 'eyJlbmMiOiJYQzIwUCJ9',
        iv: 'abc',
        ciphertext: 'def',
        tag: 'ghi'
      }
    } as unknown as IEDVChunk
    await transport.storeChunk({ docId: inserted.id, chunk })

    const read = await transport.getChunk({
      docId: inserted.id,
      chunkIndex: 0
    })
    expect(read).toEqual(chunk)
  })

  it('surfaces a missing chunk as NotFoundError', async () => {
    const inserted = await edv.insert({
      doc: { content: { note: 'no chunks written' } },
      transport
    })
    await expect(
      transport.getChunk({ docId: inserted.id, chunkIndex: 7 })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('rejects a chunk whose parent document is absent', async () => {
    await expect(
      transport.storeChunk({
        docId: 'zNonexistentDocumentId000000000000',
        chunk: {
          sequence: 0,
          index: 0,
          offset: 0,
          jwe: { ciphertext: 'x' }
        } as unknown as IEDVChunk
      })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('encrypts, chunks, stores, and reassembles a >1 chunk blob', async () => {
    // 2.5 MiB of deterministic pseudo-random bytes -- larger than the 1 MiB
    // default chunk size, so it is split into multiple stored chunks.
    const size = Math.floor(2.5 * 1024 * 1024)
    const plaintext = new Uint8Array(size)
    for (let index = 0; index < size; index++) {
      plaintext[index] = (index * 31 + 7) & 0xff
    }

    const inserted = await edv.insert({
      doc: { content: { label: 'big-blob' } },
      stream: streamOf({ bytes: plaintext, pieceSize: 256 * 1024 }),
      transport
    })

    // The document now records the chunk count the reader reassembles from.
    expect(inserted.stream?.chunks).toBeGreaterThan(1)

    const outStream = await edv.getStream({ doc: inserted, transport })
    const roundTripped = await drain(outStream)
    expect(roundTripped.length).toBe(plaintext.length)
    expect(Buffer.from(roundTripped).equals(Buffer.from(plaintext))).toBe(true)
  })
})
