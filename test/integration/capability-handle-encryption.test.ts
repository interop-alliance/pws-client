/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: a handle rebuilt from a resource-scoped capability on an
 * encryption-capable client, end to end against a live WAS server. A
 * resource-scoped grant cannot read the Collection Metadata object (WAS masks
 * the refusal as a 404), so the grantee's client cannot discover whether the
 * collection is encrypted and fails closed. `fromCapability(zcap, {
 * encryption })` is the way through: the grantee states the collection's
 * descriptor (handed over out of band with the grant) or `'plaintext'`, and
 * the handle reads and writes under the grant. Covers both an encrypted and a
 * plaintext collection, since the fail-closed discovery hits both.
 *
 * Requires a running server: `TEST_SERVER_URL`, which the global setup sets
 * when it boots one in-process. The suite skips when it is unset.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'

import { EncryptionError } from '../../src/index.js'
import type {
  CollectionEncryption,
  IDelegatedZcap,
  Resource,
  Space
} from '../../src/index.js'
import { initRecipients } from '../../src/edv/index.js'
import { makeParty } from '../helpers/party.js'
import type { Party } from '../helpers/party.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

describeLive('fromCapability with an encryption override (live server)', () => {
  let owner: Party
  let reader: Party
  let space: Space
  let descriptor: CollectionEncryption
  let vaultZcap: IDelegatedZcap
  let notesZcap: IDelegatedZcap

  /**
   * Grants the reader read and write on one resource, by its URL.
   *
   * @param url {string}
   * @returns {Promise<IDelegatedZcap>}
   */
  async function grantResource(url: string): Promise<IDelegatedZcap> {
    return owner.was.grant({
      to: reader.did,
      actions: ['GET', 'PUT'],
      target: url,
      expires: new Date(Date.now() + 60 * 60 * 1000)
    })
  }

  beforeAll(async () => {
    owner = await makeParty({ serverUrl: serverUrl! })
    reader = await makeParty({ serverUrl: serverUrl! })
    space = await owner.was.createSpace({
      name: 'Capability Handle Encryption'
    })

    // An encrypted collection whose epoch key is wrapped to owner and reader.
    const vault = await space.createCollection({
      id: 'vault',
      name: 'Vault',
      encryption: { scheme: 'edv' }
    })
    descriptor = await initRecipients({
      collection: vault,
      recipients: [owner.recipient, reader.recipient]
    })
    const secret = await space
      .collection('vault')
      .add({ note: 'encrypted', n: 1 })
    vaultZcap = await grantResource(secret.url)

    // A plaintext collection beside it.
    const notes = await space.createCollection({ id: 'notes', name: 'Notes' })
    const note = await notes.add({ note: 'plain', n: 1 })
    notesZcap = await grantResource(note.url)
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('fails closed with no override, on either collection', async () => {
    const vaultHandle = reader.was.fromCapability(vaultZcap) as Resource
    await expect(vaultHandle.get()).rejects.toThrow(EncryptionError)
    const notesHandle = reader.was.fromCapability(notesZcap) as Resource
    await expect(notesHandle.get()).rejects.toThrow(EncryptionError)
  })

  it('reads and writes an encrypted resource given the descriptor', async () => {
    const handle = reader.was.fromCapability(vaultZcap, {
      encryption: descriptor
    }) as Resource
    expect(await handle.get()).toEqual({ note: 'encrypted', n: 1 })

    await handle.put({ note: 'encrypted', n: 2 })
    // The owner, discovering the descriptor as usual, reads the reader's write.
    const asOwner = await space.collection('vault').get(handle.id)
    expect(asOwner).toEqual({ note: 'encrypted', n: 2 })
  })

  it("reads and writes a plaintext resource given 'plaintext'", async () => {
    const handle = reader.was.fromCapability(notesZcap, {
      encryption: 'plaintext'
    }) as Resource
    expect(await handle.get()).toEqual({ note: 'plain', n: 1 })

    await handle.put({ note: 'plain', n: 2 })
    expect(await space.collection('notes').get(handle.id)).toEqual({
      note: 'plain',
      n: 2
    })
  })
})
