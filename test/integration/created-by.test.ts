/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: the server-managed `createdBy` list against a live PWS
 * server. A create under a root invocation lists the invoker alone. A create
 * under a delegated capability lists the controller of each delegated
 * capability in the chain, root end first and the invoker last, with the Space
 * controller left out. Each case is read back through `describe()` /
 * `meta()`, the sync port's write ack and the `changes` feed.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { isResourceChange } from '@interop/storage-core'

import type { PwsClient } from '../../src/index.js'
import type { ActionInput, IDelegatedZcap, Space } from '../../src/index.js'
import { createPwsSyncPort } from '../../src/sync/index.js'
import { freshPwsClient } from '../helpers/liveClient.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

describeLive('createdBy delegation chain (live server)', () => {
  const actions: ActionInput[] = ['GET', 'PUT', 'POST', 'DELETE']
  let alice: PwsClient
  let aliceDid: string
  let app: PwsClient
  let appDid: string
  let agent: PwsClient
  let agentDid: string
  let space: Space
  let appZcap: IDelegatedZcap
  let agentZcap: IDelegatedZcap

  beforeAll(async () => {
    alice = await freshPwsClient()
    aliceDid = alice.controllerDid
    app = await freshPwsClient()
    appDid = app.controllerDid
    agent = await freshPwsClient()
    agentDid = agent.controllerDid

    space = await alice.createSpace({ name: 'Created By Integration' })
    const expires = new Date(Date.now() + 60 * 60 * 1000)
    // One link: the Space controller delegates the whole Space to the app.
    appZcap = await space.grant({ to: appDid, actions, expires })
    // Two links: the app delegates what it holds on to its agent.
    agentZcap = await app
      .spaceAt(space.url, { capability: appZcap })
      .grant({ to: agentDid, actions, expires })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  /**
   * Creates a Collection and a Resource in it as `pws`, and expects
   * `expected` as the `createdBy` of both on every read path.
   *
   * @param options {object}
   * @param options.pws {PwsClient}   the creating client
   * @param [options.capability] {IDelegatedZcap}   the delegated capability it
   *   invokes; omit for the Space controller's root invocation
   * @param options.collectionId {string}
   * @param options.expected {string[]}
   * @returns {Promise<void>}
   */
  async function expectCreatedBy({
    pws,
    capability,
    collectionId,
    expected
  }: {
    pws: PwsClient
    capability?: IDelegatedZcap
    collectionId: string
    expected: string[]
  }): Promise<void> {
    const collection = await pws
      .spaceAt(space.url, { capability })
      .createCollection({ id: collectionId, name: collectionId })
    expect((await collection.describe())?.createdBy).toEqual(expected)

    // The write ack of the create carries the list.
    const port = createPwsSyncPort({
      pws,
      spaceUrl: space.url,
      collectionId,
      capability
    })
    const ack = await port.putContent({
      id: 'doc',
      data: { hello: 'world' },
      ifNoneMatch: true
    })
    expect(ack?.createdBy).toEqual(expected)

    expect((await collection.resource('doc').meta())?.createdBy).toEqual(
      expected
    )
    expect((await port.get({ id: 'doc' }))?.createdBy).toEqual(expected)

    // The feed carries it, through the port and through the handle.
    const pulled = await port.query({ limit: 50 })
    expect(pulled.documents.find(doc => doc.id === 'doc')?.createdBy).toEqual(
      expected
    )
    const page = await collection.changes()
    const fed = page.documents
      .filter(isResourceChange)
      .find(doc => doc.id === 'doc')
    expect(fed?.createdBy).toEqual(expected)
  }

  it('a root create lists the invoker alone', async () => {
    expect((await space.describe())?.createdBy).toEqual([aliceDid])
    await expectCreatedBy({
      pws: alice,
      collectionId: 'by-root',
      expected: [aliceDid]
    })
  })

  it('a one-link delegated create lists the delegee', async () => {
    await expectCreatedBy({
      pws: app,
      capability: appZcap,
      collectionId: 'by-app',
      expected: [appDid]
    })
  })

  it('a two-link chain lists each delegee, the invoker last', async () => {
    await expectCreatedBy({
      pws: agent,
      capability: agentZcap,
      collectionId: 'by-agent',
      expected: [appDid, agentDid]
    })
  })
})
