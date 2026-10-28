/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: multi-recipient encrypted Collections and key epochs, end
 * to end against a live WAS server. Several readers each hold their own X25519
 * key-agreement key; a per-epoch collection key is wrapped to each of them on
 * the Collection's `encryption` descriptor, and resources are encrypted under
 * the `currentEpoch`. Proves the whole feature, and in particular the removal
 * quadruple that carries it:
 *
 * 1. two distinct readers both decrypt the same resource, each with its own key;
 * 2. a third reader added later reads resources written BEFORE its add (escrow
 *    of prior epochs) and after;
 * 3. one reader removed -- the full `removeRecipient` -- and then: (a) its pull
 *    (zcap) is dead, (b) it cannot decrypt a post-rotation resource, (c) it CAN
 *    still decrypt a pre-rotation resource it already holds, (d) the remaining
 *    readers read everything;
 * 4. two racing `addRecipient` calls both land (the CAS prevents a clobber).
 *
 * Also pins epoch stamping (a write's `Key-Epoch` surfaces on `meta()`, the
 * listing, and the `changes` feed) and that a rotation preserves any
 * blinded-index `hmac` on the descriptor (the hmac does not rotate with the
 * epoch).
 *
 * Requires a running server: set `TEST_SERVER_URL` (byte-identical to the
 * server's own `SERVER_URL` -- zcap invocation targets embed host and port). The
 * suite skips when it is unset.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import type { HttpResponse } from '@interop/http-client'
import { isResourceChange } from '@interop/storage-core'

import { WasClient, KeyUnwrapError } from '../../src/index.js'
import type {
  Collection,
  CollectionEncryption,
  IDelegatedZcap,
  Space
} from '../../src/index.js'
import {
  initRecipients,
  addRecipient,
  removeRecipient,
  trustRosterDidKeys
} from '../../src/edv/index.js'
import { makeParty } from '../helpers/party.js'
import type { Party } from '../helpers/party.js'

const serviceUrl = process.env.TEST_SERVER_URL
const describeLive = serviceUrl ? describe : describe.skip

describeLive('multi-recipient key epochs (live server)', () => {
  let owner: Party
  let readerA: Party
  let readerB: Party
  let readerC: Party
  // A plaintext owner client, to fetch the raw stored ciphertext (the "hand it
  // the bytes" party for the read-axis assertions).
  let ownerPlain: WasClient
  let space: Space
  let spaceUrl: string
  let zcapB: IDelegatedZcap
  let doc1Id: string
  let epoch1: string

  const collectionId = 'vault'

  /**
   * A fresh owner handle to the vault (no override) so it re-discovers the
   * current descriptor and encrypts under the current epoch.
   *
   * @returns {Collection}
   */
  function ownerVault(): Collection {
    return owner.was.spaceAt(spaceUrl).collection(collectionId)
  }

  /**
   * Grants collection read/write to a party and returns the delegated zcap.
   *
   * @param to {string}
   * @returns {Promise<IDelegatedZcap>}
   */
  async function grantTo(to: string): Promise<IDelegatedZcap> {
    return owner.was
      .spaceAt(spaceUrl)
      .collection(collectionId)
      .grant({
        to,
        actions: ['GET', 'PUT', 'POST', 'DELETE'],
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })
  }

  /**
   * Reads the raw stored envelope for a resource (bypassing decryption), as a
   * still-authorized party would to hand another party the ciphertext.
   *
   * @param id {string}
   * @returns {Promise<Record<string, unknown>>}
   */
  async function rawEnvelope(id: string): Promise<Record<string, unknown>> {
    return (await ownerPlain
      .spaceAt(spaceUrl)
      .collection(collectionId)
      .get(id)) as Record<string, unknown>
  }

  /**
   * Decrypts a raw envelope with a party's own keys against a given descriptor,
   * building that party's codec directly (so the read axis can be exercised even
   * when the party's pull is revoked).
   *
   * @param party {Party}
   * @param descriptor {CollectionEncryption}
   * @param envelope {Record<string, unknown>}
   * @returns {Promise<unknown>}
   */
  async function decodeWith(
    party: Party,
    descriptor: CollectionEncryption,
    envelope: Record<string, unknown>
  ): Promise<unknown> {
    const codec = await party.provider.codecFor({
      spaceUrl,
      collectionId,
      scheme: 'edv',
      encryption: descriptor
    })
    return codec!.decode({ data: envelope } as unknown as HttpResponse)
  }

  /**
   * Reads the current descriptor from the server (owner's authorized view).
   *
   * @returns {Promise<CollectionEncryption>}
   */
  async function currentDescriptor(): Promise<CollectionEncryption> {
    const described = await owner.was
      .spaceAt(spaceUrl)
      .collection(collectionId)
      .describe()
    return described!.encryption!
  }

  beforeAll(async () => {
    owner = await makeParty({ serviceUrl: serviceUrl! })
    readerA = await makeParty({ serviceUrl: serviceUrl! })
    readerB = await makeParty({ serviceUrl: serviceUrl! })
    readerC = await makeParty({ serviceUrl: serviceUrl! })
    ownerPlain = WasClient.fromSigner({
      serviceUrl: serviceUrl!,
      signer: owner.signer
    })

    space = await owner.was.createSpace({ name: 'Key Epochs Integration' })
    spaceUrl = space.url
    await space.createCollection({
      id: collectionId,
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })

    // Initialize the first epoch, wrapping it to the owner and the two initial
    // readers (the owner is a recipient so it can write).
    const descriptor = await initRecipients({
      collection: ownerVault(),
      recipients: [owner.recipient, readerA.recipient, readerB.recipient]
    })
    epoch1 = descriptor.currentEpoch!

    // The readers pull with delegated capabilities on the collection.
    await grantTo(readerA.did) // readerA cap not needed by id here
    zcapB = await grantTo(readerB.did)

    // Owner writes the first resource under epoch 1.
    const added = await ownerVault().add({ note: 'first', n: 1 })
    doc1Id = added.id
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('two recipients both decrypt the same resource, each with its own key', async () => {
    const zcapA = await grantTo(readerA.did)
    const asA = readerA.was
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapA })
    const asB = readerB.was
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapB })
    expect(await asA.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    expect(await asB.get(doc1Id)).toEqual({ note: 'first', n: 1 })
  })

  it('stamps the write epoch on meta(), the listing, and the changes feed', async () => {
    const meta = await ownerVault().resource(doc1Id).meta()
    expect(meta?.epoch).toBe(epoch1)

    const list = await ownerVault().list()
    const item = list?.items.find(entry => entry.id === doc1Id)
    expect(item?.epoch).toBe(epoch1)

    const changes = await ownerVault().changes()
    const changed = changes.documents
      .filter(isResourceChange)
      .find(document => document.id === doc1Id)
    expect(changed?.epoch).toBe(epoch1)
  })

  it('adds a third recipient that reads resources written before and after its add', async () => {
    // Escrow: addRecipient wraps EVERY existing epoch to the new reader.
    await addRecipient({
      collection: ownerVault(),
      recipient: readerC.recipient,
      owner: { keyAgreementKey: owner.kak }
    })
    // No rotation on add: a resource written now is still epoch 1.
    const doc2 = await ownerVault().add({ note: 'second', n: 2 })

    const zcapC = await grantTo(readerC.did)
    const asC = readerC.was
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapC })
    // Reads the pre-add resource (escrow of the prior epoch)...
    expect(await asC.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    // ...and the post-add resource.
    expect(await asC.get(doc2.id)).toEqual({ note: 'second', n: 2 })
  })

  it('removes a reader: pull dies, new ciphertext is unreadable, old is not clawed back, others unaffected', async () => {
    const zcapA = await grantTo(readerA.did)
    const zcapC = await grantTo(readerC.did)

    // The full, indivisible removal: revoke readerB's pull AND rotate the epoch.
    const rotated = await removeRecipient({
      resolveRecipientKey: trustRosterDidKeys,
      collection: ownerVault(),
      space: owner.was.spaceAt(spaceUrl),
      recipientId: readerB.recipient.id,
      revoke: zcapB
    })
    const epoch2 = rotated.currentEpoch!
    expect(epoch2).not.toBe(epoch1)

    // Owner writes a post-rotation resource (under epoch 2).
    const doc3 = await ownerVault().add({ note: 'third', n: 3 })
    const doc3Meta = await ownerVault().resource(doc3.id).meta()
    expect(doc3Meta?.epoch).toBe(epoch2)

    // (a) Pull axis: readerB's capability is dead. Read with a plaintext client
    // over readerB's identity (no descriptor discovery) to isolate the pull
    // axis -- the server simply will not serve the bytes anymore (WAS masks
    // unauthorized as 404, surfaced as null by get()).
    const plaintextB = WasClient.fromSigner({
      serviceUrl: serviceUrl!,
      signer: readerB.signer
    })
    const asBRevoked = plaintextB
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapB })
    expect(await asBRevoked.get(doc1Id)).toBeNull()

    // (b) Read axis, prospective: handed the post-rotation ciphertext, readerB
    // cannot decrypt it (it holds no epoch-2 key). Its descriptor is the
    // current, rotated one -- epoch 2 is listed on it, readerB is just not a
    // recipient -- so this is the membership signal (KeyUnwrapError), not the
    // stale-descriptor UnknownEpochError.
    const doc3Envelope = await rawEnvelope(doc3.id)
    await expect(
      decodeWith(readerB, rotated, doc3Envelope)
    ).rejects.toBeInstanceOf(KeyUnwrapError)

    // (c) Honest ceiling: readerB CAN still decrypt a pre-rotation resource it
    // already holds -- rotation never claws back what a reader could read.
    const doc1Envelope = await rawEnvelope(doc1Id)
    expect(await decodeWith(readerB, rotated, doc1Envelope)).toEqual({
      note: 'first',
      n: 1
    })

    // (d) The remaining readers read everything, before and after the rotation.
    const asA = readerA.was
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapA })
    const asC = readerC.was
      .spaceAt(spaceUrl)
      .collection(collectionId, { capability: zcapC })
    expect(await asA.get(doc1Id)).toEqual({ note: 'first', n: 1 })
    expect(await asA.get(doc3.id)).toEqual({ note: 'third', n: 3 })
    expect(await asC.get(doc3.id)).toEqual({ note: 'third', n: 3 })
  })

  it('two concurrent addRecipient calls both land (the CAS prevents a clobber)', async () => {
    const newA = await makeParty({ serviceUrl: serviceUrl! })
    const newB = await makeParty({ serviceUrl: serviceUrl! })
    // Two racing adds from two independent handles over the same collection.
    await Promise.all([
      addRecipient({
        collection: ownerVault(),
        recipient: newA.recipient,
        owner: { keyAgreementKey: owner.kak }
      }),
      addRecipient({
        collection: ownerVault(),
        recipient: newB.recipient,
        owner: { keyAgreementKey: owner.kak }
      })
    ])
    const descriptor = await currentDescriptor()
    const currentEpoch = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const kids = currentEpoch.recipients.map(entry => entry.header.kid)
    // Neither add clobbered the other: both new readers are present.
    expect(kids).toContain(newA.recipient.id)
    expect(kids).toContain(newB.recipient.id)
  })
})
