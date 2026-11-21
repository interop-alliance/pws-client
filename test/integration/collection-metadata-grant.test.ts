/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: which grant a Collection Metadata write needs. The server
 * admits `PUT .../meta` under a root invocation, or under a delegated
 * capability that targets exactly the Space URL. A grant on the Collection
 * itself is answered the masked 404, which the handle reports as
 * `SpaceGrantRequiredError` before sending.
 *
 * Runs against a live `@interop/web-spaces-server` at the URL named by
 * `TEST_SERVER_URL`. The suite skips when it is unset, so a bare
 * `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'

import {
  NotFoundError,
  SpaceGrantRequiredError,
  httpStatus
} from '../../src/index.js'
import type {
  ActionInput,
  Collection,
  IDelegatedZcap,
  PwsClient,
  Space
} from '../../src/index.js'
import { collectionMetaUrl } from '../../src/paths/index.js'
import { freshPwsClient } from '../helpers/liveClient.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

describeLive('the grant a Collection Metadata write needs', () => {
  const actions: ActionInput[] = ['GET', 'PUT', 'POST', 'DELETE']
  let alice: PwsClient
  let app: PwsClient
  let space: Space
  let notes: Collection
  let collectionZcap: IDelegatedZcap
  let spaceZcap: IDelegatedZcap

  beforeAll(async () => {
    alice = await freshPwsClient()
    app = await freshPwsClient()
    space = await alice.createSpace({ name: 'Metadata Grant Integration' })
    notes = await space.createCollection({ id: 'notes', name: 'Notes' })
    const expires = new Date(Date.now() + 60 * 60 * 1000)
    collectionZcap = await notes.grant({
      to: app.controllerDid,
      actions,
      expires
    })
    spaceZcap = await space.grant({ to: app.controllerDid, actions, expires })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('refuses a write under a Collection-scoped grant, naming the cause', async () => {
    const scoped = app
      .spaceAt(space.url)
      .collection('notes', { capability: collectionZcap })
    // The grant does cover the read and a Resource write.
    expect((await scoped.describe())?.name).toBe('Notes')
    await scoped.put('doc', { hello: 'world' })

    for (const write of [
      () => scoped.setName('Renamed By App'),
      () => scoped.configure({ name: 'Renamed By App' }),
      () => scoped.replaceDescription({ name: 'Renamed By App' })
    ]) {
      const refusal = await write().catch((err: unknown) => err)
      expect(refusal).toBeInstanceOf(SpaceGrantRequiredError)
      expect(refusal).toBeInstanceOf(NotFoundError)
    }
    expect((await notes.describe())?.name).toBe('Notes')
  })

  it('the server answers that write the masked 404', async () => {
    // Sent raw, past the handle's own check, to pin the rule it stands for.
    const refusal = await app
      .request({
        url: collectionMetaUrl({ spaceUrl: space.url, collectionId: 'notes' }),
        method: 'PUT',
        capability: collectionZcap,
        json: { id: 'notes', name: 'Renamed By App' }
      })
      .catch((err: unknown) => err)
    expect(httpStatus(refusal)).toBe(404)
    expect((await notes.describe())?.name).toBe('Notes')
  })

  it('admits the write under a delegated grant on the Space URL', async () => {
    const wide = app
      .spaceAt(space.url, { capability: spaceZcap })
      .collection('notes')
    await wide.configure({ name: 'Renamed By App' })
    expect((await notes.describe())?.name).toBe('Renamed By App')
  })
})
