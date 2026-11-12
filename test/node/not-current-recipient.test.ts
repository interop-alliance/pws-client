/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A reader removed by `removeRecipient` is named in the older epoch and not in
 * the current one. It keeps reading what was written before the rotation, and
 * every write through its Collection handle or its cipher is refused with
 * `NotCurrentRecipientError` before any request is sent. The encrypt-only
 * build is a different role and still seals to the current epoch.
 */
import { describe, it, expect } from 'vitest'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { EncryptionError, NotCurrentRecipientError } from '../../src/index.js'
import type { CollectionEncryption, Json } from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import type { Space } from '../../src/Space.js'
import {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  addRecipient,
  didKeyResolver,
  removeRecipient,
  trustRosterDidKeys
} from '../../src/edv/index.js'
import { collectionMetaUrl } from '../../src/internal/paths.js'
import { memoryServer } from '../helpers/memoryServer.js'
import { memoryDescriptorHolder } from '../helpers/descriptorHolder.js'
import { makeDidKeyKak } from '../helpers/party.js'
import { epochDescriptorFor } from '../helpers/readerKeys.js'
import { spaceUrlFor } from '../helpers/stubClient.js'

const COLLECTION_ID = 'c'

/**
 * A Collection handle with no per-handle `encryption` override: it discovers
 * the descriptor from the server's stored Collection Metadata, and its
 * keystore answers with `keyAgreementKey`.
 *
 * @param options {object}
 * @param options.server {object}   a `memoryServer`
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @returns {Collection}
 */
function handleDiscovering({
  server,
  keyAgreementKey
}: {
  server: ReturnType<typeof memoryServer>
  keyAgreementKey: IKeyAgreementKey
}): Collection {
  return server
    .client({
      maxBlobBytes: 1024,
      chunkSize: 1024,
      resolveKeys: async () => ({
        keyAgreementKey,
        keyResolver: didKeyResolver
      })
    })
    .spaceAt(spaceUrlFor('s'))
    .collection(COLLECTION_ID)
}

/**
 * The in-memory server path of a handle's Collection Metadata object.
 *
 * @param collection {Collection}
 * @returns {string}
 */
function metaPathOf(collection: Collection): string {
  return new URL(
    collectionMetaUrl({
      spaceUrl: collection.spaceUrl,
      collectionId: COLLECTION_ID
    })
  ).pathname
}

/**
 * Stores a handle's Collection Metadata on the in-memory server directly, as
 * another writer would have left it.
 *
 * @param options {object}
 * @param options.server {object}   a `memoryServer`
 * @param options.collection {Collection}
 * @param options.members {object}   the members beside `id` and `type`
 * @returns {string}   the server path written
 */
function storeMeta({
  server,
  collection,
  members
}: {
  server: ReturnType<typeof memoryServer>
  collection: Collection
  members: { custom?: Json; encryption?: CollectionEncryption }
}): string {
  const path = metaPathOf(collection)
  server.write(
    path,
    new TextEncoder().encode(
      JSON.stringify({ id: COLLECTION_ID, type: ['Collection'], ...members })
    )
  )
  return path
}

/**
 * Two readers sharing one epoch, then the second removed with the real
 * `removeRecipient` over an in-memory descriptor holder.
 *
 * @returns {Promise<object>}   both readers' keys, and the descriptor before
 *   and after the removal
 */
async function removedReader(): Promise<{
  alice: IKeyAgreementKey
  bob: IKeyAgreementKey
  bobRecipient: { id: string; publicKeyMultibase: string }
  before: CollectionEncryption
  rotated: CollectionEncryption
}> {
  const alice = await makeDidKeyKak()
  const bob = await makeDidKeyKak()
  const before = await epochDescriptorFor([alice.kak, bob.kak])
  const { collection } = memoryDescriptorHolder(before, COLLECTION_ID)
  const rotated = await removeRecipient({
    resolveRecipientKey: trustRosterDidKeys,
    collection,
    space: { revoke: async () => undefined } as unknown as Space,
    recipientId: bob.kak.id,
    revoke: []
  })
  return {
    alice: alice.kak,
    bob: bob.kak,
    bobRecipient: bob.recipient,
    before,
    rotated
  }
}

describe('a reader removed by removeRecipient', () => {
  it('reads through its Collection handle and is refused every write before any request', async () => {
    const { alice, bob, before, rotated } = await removedReader()
    expect(rotated.currentEpoch).not.toBe(before.currentEpoch)
    const server = memoryServer()
    const handleFor = (
      keyAgreementKey: IKeyAgreementKey,
      encryption: CollectionEncryption
    ): Collection =>
      server
        .client({ maxBlobBytes: 1024, chunkSize: 1024 })
        .spaceAt(spaceUrlFor('s'))
        .collection(COLLECTION_ID, {
          encryption: {
            ...encryption,
            keys: { keyAgreementKey, keyResolver: didKeyResolver }
          }
        })
    // Written before the rotation, under the epoch that names both readers.
    const { id } = await handleFor(alice, before).add({ note: 'first' })

    const asBob = handleFor(bob, rotated)
    expect(await asBob.get(id)).toEqual({ note: 'first' })

    const seen: string[] = []
    server.beforeRequest.run = (args, path) => {
      seen.push(`${args.method ?? 'GET'} ${path}`)
    }
    const writes = [
      () => asBob.add({ note: 'second' }),
      () => asBob.put(id, { note: 'changed' }),
      () => asBob.add(new Blob([new Uint8Array(4096)])),
      () => asBob.resource(id).setMeta({ custom: { name: 'renamed' } }),
      () => asBob.setMeta({ custom: { name: 'renamed' } }),
      () => asBob.setName('renamed'),
      () => asBob.setTags({ team: 'a' }),
      () => asBob.resource(id).setName('renamed'),
      () => asBob.resource(id).setTags({ team: 'a' }),
      // The descriptor declares no blinded index. The refusal still comes
      // first, ahead of the no-client-side-index ValidationError.
      () => asBob.declareIndex({ attribute: 'note' }),
      () => asBob.declareIndexes({ indexes: [{ attribute: 'note' }] })
    ]
    for (const write of writes) {
      const failure = await write().catch((err: unknown) => err)
      expect(failure).toBeInstanceOf(NotCurrentRecipientError)
      expect(failure).toBeInstanceOf(EncryptionError)
      expect((failure as Error).name).toBe('NotCurrentRecipientError')
    }
    expect(seen).toEqual([])
    // The refusals changed nothing about its reads.
    expect(await asBob.get(id)).toEqual({ note: 'first' })
  })

  it('decrypts history with its cipher and is refused encrypt and encryptUpdate', async () => {
    const { alice, bob, before, rotated } = await removedReader()
    const cipherFor = (
      keyAgreementKey: IKeyAgreementKey,
      encryption: CollectionEncryption
    ) =>
      createEdvDocCipher({
        keyAgreementKey,
        keyResolver: didKeyResolver,
        collectionId: COLLECTION_ID,
        idDerivation: 'random',
        encryption
      })
    const asAlice = await cipherFor(alice, before)
    const stored = await asAlice.encrypt({ data: { note: 'first' } })

    const asBob = await cipherFor(bob, rotated)
    expect(
      await asBob.decrypt({ id: stored.id, envelope: stored.envelope })
    ).toEqual({ note: 'first' })
    await expect(
      asBob.encrypt({ data: { note: 'second' } })
    ).rejects.toBeInstanceOf(NotCurrentRecipientError)
    await expect(
      asBob.encryptUpdate!({
        id: stored.id,
        data: { note: 'changed' },
        current: stored.envelope
      })
    ).rejects.toBeInstanceOf(NotCurrentRecipientError)
  })

  it('refuses a scheme-changing configure that would re-seal custom, and sends no PUT', async () => {
    const { bob, rotated } = await removedReader()
    const server = memoryServer()
    const bobHandle = handleDiscovering({ server, keyAgreementKey: bob })
    const path = storeMeta({
      server,
      collection: bobHandle,
      members: { custom: { name: 'Notes', tags: { team: 'a' } } }
    })
    const before = server.store.get(path)

    const seen: string[] = []
    server.beforeRequest.run = (args, requestPath) => {
      seen.push(`${args.method ?? 'GET'} ${requestPath}`)
    }
    const failure = await bobHandle
      .configure({ encryption: rotated })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotCurrentRecipientError)
    expect(seen.filter(entry => entry.startsWith('PUT'))).toEqual([])
    expect(server.store.get(path)).toBe(before)
  })

  it('is not sticky: the same discovering handle writes once the stored descriptor names it', async () => {
    const { alice, bob, bobRecipient, rotated } = await removedReader()
    const server = memoryServer()
    const bobHandle = handleDiscovering({ server, keyAgreementKey: bob })
    const store = (encryption: CollectionEncryption): string =>
      storeMeta({ server, collection: bobHandle, members: { encryption } })
    store(rotated)

    const failure = await bobHandle
      .add({ note: 'refused' })
      .catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotCurrentRecipientError)

    // An owner re-adds bob with the real addRecipient: he now holds every
    // epoch's key, the current one included.
    const { collection, state } = memoryDescriptorHolder(rotated, COLLECTION_ID)
    await addRecipient({
      collection,
      recipient: bobRecipient,
      owner: { keyAgreementKey: alice }
    })
    store(state.encryption)

    const { id } = await bobHandle.add({ note: 'accepted' })
    expect(await bobHandle.get(id)).toEqual({ note: 'accepted' })
  })

  it('leaves the encrypt-only build sealing to the current epoch', async () => {
    const { alice, rotated } = await removedReader()
    const writer = await createEdvEncryptOnlyDocCipher({
      collectionId: COLLECTION_ID,
      encryption: rotated
    })
    const stored = await writer.encrypt({ data: { note: 'sealed' } })
    expect(stored.epoch).toBe(rotated.currentEpoch)
    const reader = await createEdvDocCipher({
      keyAgreementKey: alice,
      keyResolver: didKeyResolver,
      collectionId: COLLECTION_ID,
      encryption: rotated
    })
    expect(
      await reader.decrypt({ id: stored.id, envelope: stored.envelope as Json })
    ).toEqual({ note: 'sealed' })
  })
})
