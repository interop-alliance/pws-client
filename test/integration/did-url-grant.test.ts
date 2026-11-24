/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: a delegate holding a grant in DID URL form. The Space is
 * promoted to a `did:webvh` whose document carries `PathHandler` services, so
 * `did:webvh:<scid>:.../photos/` names the Space's `photos` Collection. The
 * chain roots in `urn:zcap:root:<encoded DID URL>`, and every link names a
 * DID URL. The delegate's client dereferences both to find the Space and
 * what the handle addresses.
 *
 * The grants are minted with ezcap directly, so the suite can also mint the
 * chains a handle refuses to issue. The delegate's dereferencer is the
 * built-in one over a `fetch` that serves the DID's history log from memory.
 *
 * Runs against a live `@interop/web-spaces-server` at the URL named by
 * `TEST_SERVER_URL`. The suite skips when it is unset, so a bare
 * `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import {
  getFileUrl,
  logToJsonlString,
  updateDID
} from '@interop/did-method-webvh'
import type { DIDLog } from '@interop/did-method-webvh'
import { provisionWebvhIdentity } from '@interop/web-spaces-server/testing'

import {
  AUTHZ_PROFILE_SPEC_ID,
  Collection,
  NotFoundError,
  PwsClient,
  Resource,
  Space,
  SpaceGrantRequiredError,
  TargetDereferenceError
} from '../../src/index.js'
import type { ISigner, IZcap } from '../../src/index.js'
import { createTargetDereferencer } from '../../src/did-url.js'
import { rootCapabilityId, spaceMetaUrl } from '../../src/paths/index.js'
import { freshPwsClient } from '../helpers/liveClient.js'
import { pathHandler } from '../helpers/pathHandler.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

describeLive('a delegate holding a DID-form grant (live server)', () => {
  let alice: PwsClient
  let owner: PwsClient
  let bob: PwsClient
  let did: string
  let spaceUrl: string
  let otherSpace: Space
  let log: DIDLog
  let logSigner: Parameters<typeof updateDID>[0]['signer']

  /**
   * A grant to the delegate, signed by the Space's controller.
   *
   * @param options {object}
   * @param options.root {string}   the target of the chain's root capability
   * @param options.target {string}   the grant's invocation target
   * @returns {Promise<IZcap>}
   */
  async function grant({
    root,
    target
  }: {
    root: string
    target: string
  }): Promise<IZcap> {
    return owner.zcapClient.delegate({
      capability: rootCapabilityId(root),
      invocationTarget: target,
      controller: bob.controllerDid,
      allowedActions: ['GET', 'PUT'],
      expires: new Date(Date.now() + 60 * 60 * 1000)
    })
  }

  beforeAll(async () => {
    alice = await freshPwsClient()
    const info = await alice.service()
    expect(
      info.hasFeature({
        spec: AUTHZ_PROFILE_SPEC_ID,
        feature: 'did-url-targets'
      })
    ).toBe(true)

    otherSpace = await alice.createSpace({ name: 'Other Space' })
    await otherSpace.collection('photos').configure({ force: true })
    await otherSpace.collection('photos').put('doc-1', { photo: 'other' })

    const account = await provisionWebvhIdentity({
      owner: { did: alice.controllerDid, pws: alice },
      baseServerUrl: baseServerUrl as string
    })
    ;({ did, spaceUrl } = account)
    logSigner = account.logSigner
    const updated = await updateDID({
      log: account.log,
      signer: account.logSigner,
      services: [
        pathHandler({ path: '/', serviceEndpoint: spaceUrl }),
        pathHandler({ path: '/other', serviceEndpoint: otherSpace.url })
      ]
    })
    log = updated.log
    await alice.request({
      url: `${spaceUrl}id/did.jsonl`,
      method: 'PUT',
      headers: { 'content-type': 'text/jsonl' },
      body: new Blob([logToJsonlString(log)], { type: 'text/jsonl' })
    })

    const space = alice.spaceAt(spaceUrl)
    await space.collection('photos').configure({ force: true, name: 'Photos' })
    await space.collection('photos').put('doc-1', { photo: 1 })
    await space.collection('albums').configure({ force: true })
    await space.collection('albums').put('a-1', { album: 1 })

    // Promote the Space to the DID, so a chain rooted in its DID URL is
    // one the Space's controller signed.
    await alice.request({
      url: spaceMetaUrl({ spaceUrl }),
      method: 'PUT',
      json: { id: account.spaceId, name: 'Identity Space', controller: did }
    })
    owner = PwsClient.fromSigner({
      baseServerUrl: baseServerUrl as string,
      signer: account.clientKeyPair.signer() as ISigner
    })

    const logUrl = getFileUrl(did)
    const bobKeys = await freshPwsClient()
    bob = new PwsClient({
      baseServerUrl: baseServerUrl as string,
      zcapClient: bobKeys.zcapClient,
      dereferenceTarget: createTargetDereferencer({
        fetch: async (input: string) =>
          input === logUrl
            ? new Response(logToJsonlString(log), { status: 200 })
            : new Response('not found', { status: 404 })
      })
    })
  })

  afterAll(async () => {
    for (const space of [owner?.spaceAt(spaceUrl), otherSpace]) {
      try {
        await space?.delete()
      } catch {
        /* best-effort cleanup */
      }
    }
  })

  it('reads and writes under a Collection grant', async () => {
    const photos = await bob.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/` })
    )
    expect(photos).toBeInstanceOf(Collection)
    expect(photos.url).toBe(`${spaceUrl}photos/`)
    const collection = photos as Collection
    expect(await collection.get('doc-1')).toEqual({ photo: 1 })
    await collection.put('doc-2', { photo: 2 })
    expect(
      await owner.spaceAt(spaceUrl).collection('photos').get('doc-2')
    ).toEqual({ photo: 2 })
    expect((await collection.describe())?.name).toBe('Photos')
  })

  it('reads under a Resource grant, at that Resource only', async () => {
    const resource = await bob.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/doc-1` })
    )
    expect(resource).toBeInstanceOf(Resource)
    expect(await (resource as Resource).get()).toEqual({ photo: 1 })
  })

  it('a Space grant navigates, and makes a Collection Metadata write', async () => {
    const space = await bob.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/` })
    )
    expect(space).toBeInstanceOf(Space)
    expect(space.url).toBe(spaceUrl)
    const albums = (space as Space).collection('albums')
    expect(await albums.get('a-1')).toEqual({ album: 1 })
    await albums.configure({ name: 'Albums' })
    expect(
      (await owner.spaceAt(spaceUrl).collection('albums').describe())?.name
    ).toBe('Albums')
  })

  it('refuses a Collection Metadata write under a Collection grant', async () => {
    const photos = (await bob.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/` })
    )) as Collection
    await expect(photos.setName('Renamed')).rejects.toBeInstanceOf(
      SpaceGrantRequiredError
    )
  })

  it('answers a request outside the grant without sending it', async () => {
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const albums = bob
      .spaceAt(spaceUrl)
      .collection('albums', { capability: zcap })
    expect(await albums.get('a-1')).toBeNull()
    await expect(albums.put('a-2', { album: 2 })).rejects.toBeInstanceOf(
      NotFoundError
    )
  })

  it('is refused at another Space', async () => {
    // The DID's `/other` path names a Space the DID does not control, so
    // the server refuses a chain rooted there.
    const photos = (await bob.fromCapability(
      await grant({ root: `${did}/other/`, target: `${did}/other/photos/` })
    )) as Collection
    expect(photos.url).toBe(`${otherSpace.url}photos/`)
    expect(await photos.get('doc-1')).toBeNull()
    await expect(photos.put('doc-9', { photo: 9 })).rejects.toBeInstanceOf(
      NotFoundError
    )
    expect(await otherSpace.collection('photos').get('doc-9')).toBeNull()
  })

  it('is refused when the chain mixes the two forms', async () => {
    for (const mixed of [
      { root: `${did}/`, target: `${spaceUrl}photos/` },
      { root: spaceUrl, target: `${did}/photos/` }
    ]) {
      const photos = (await bob.fromCapability(
        await grant(mixed)
      )) as Collection
      expect(photos.url).toBe(`${spaceUrl}photos/`)
      expect(await photos.get('doc-1')).toBeNull()
      await expect(photos.put('doc-8', { photo: 8 })).rejects.toBeInstanceOf(
        NotFoundError
      )
    }
    expect(
      await owner.spaceAt(spaceUrl).collection('photos').get('doc-8')
    ).toBeNull()
  })

  it('reports a handle the Space has moved away from', async () => {
    // The delegate's own copy of the log, so the repoint stays in this test.
    let served = log
    const logUrl = getFileUrl(did)
    /**
     * A dereferencer with an empty cache, over the log served now.
     *
     * @returns {ReturnType<typeof createTargetDereferencer>}
     */
    function freshDereferencer(): ReturnType<typeof createTargetDereferencer> {
      return createTargetDereferencer({
        fetch: async (input: string) =>
          input === logUrl
            ? new Response(logToJsonlString(served), { status: 200 })
            : new Response('not found', { status: 404 })
      })
    }
    let dereferenceTarget = freshDereferencer()
    const delegate = new PwsClient({
      baseServerUrl: baseServerUrl as string,
      zcapClient: bob.zcapClient,
      dereferenceTarget: async input => dereferenceTarget(input)
    })
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const photos = (await delegate.fromCapability(zcap)) as Collection
    expect(await photos.get('doc-1')).toEqual({ photo: 1 })

    // Repoint the DID's `PathHandler` at another Space, and drop the cache.
    const repointed = await updateDID({
      log: served,
      signer: logSigner,
      services: [pathHandler({ path: '/', serviceEndpoint: otherSpace.url })]
    })
    served = repointed.log
    dereferenceTarget = freshDereferencer()

    await expect(photos.get('doc-1')).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
    await expect(photos.resource('doc-1').delete()).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
    expect(
      await owner.spaceAt(spaceUrl).collection('photos').get('doc-1')
    ).toEqual({ photo: 1 })

    const moved = await delegate.fromCapability(zcap)
    expect(moved.url).toBe(`${otherSpace.url}photos/`)
  })
})
