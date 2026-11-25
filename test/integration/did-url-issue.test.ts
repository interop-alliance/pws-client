/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: a Space controller issuing grants in DID URL form from a
 * Space handle built with `didUrl`, and the Space then moving to a second
 * server with those grants unchanged.
 *
 * The suite boots two servers of its own, each over a temp-dir backend. The
 * user's `did:webvh` is hosted on neither. Both servers resolve it through a
 * `peerLogFetcher` that serves one shared log from memory, and the clients'
 * dereferencers read the same log. The document maps `/` to the Space on
 * server one. The move is Export Space on server one, Import Space on server
 * two, then a new log entry that repoints the `PathHandler`.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import {
  createDID,
  getFileUrl,
  logToJsonlString,
  updateDID
} from '@interop/did-method-webvh'
import type { DIDLog, Signer } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  openTempBackend,
  startTestServer,
  webvhLogSigner
} from '@interop/web-spaces-server/testing'

import {
  AUTHZ_PROFILE_SPEC_ID,
  Collection,
  NotFoundError,
  NotSupportedError,
  PwsClient,
  Resource,
  Space,
  TargetDereferenceError,
  ValidationError
} from '../../src/index.js'
import type {
  IDelegatedZcap,
  ISigner,
  ServiceDescription
} from '../../src/index.js'
import { createTargetDereferencer } from '../../src/did-url.js'
import { rootCapabilityId } from '../../src/paths/index.js'
import { pathHandler } from '../helpers/pathHandler.js'

describe('a controller issuing DID-form grants (live servers)', () => {
  const spaceId = `moving-${Date.now().toString(36)}`
  const expires = new Date(Date.now() + 60 * 60 * 1000)
  let one: Awaited<ReturnType<typeof startTestServer>>
  let two: Awaited<ReturnType<typeof startTestServer>>
  let log: DIDLog
  let logSigner: Signer
  let logUrl: string
  let did: string
  let didUrl: string
  /**
   * How many times a client or a server fetched the user's log.
   */
  let logFetches = 0
  let aliceSigner: ISigner
  let bobSigner: ISigner
  let carolSigner: ISigner
  let alice: PwsClient
  let space: Space
  let photosGrant: IDelegatedZcap
  /**
   * A Collection handle opened on a DID URL while the Space is on server one.
   */
  let openedBeforeMove: Collection

  /**
   * The user's log, as its host serves it now.
   *
   * @param url {string}
   * @returns {string}
   */
  function servedLog(url: string): string {
    if (url !== logUrl) {
      throw new Error(`No log is served at ${url}.`)
    }
    logFetches++
    return logToJsonlString(log)
  }

  /**
   * A server whose peer resolver fetches the shared log.
   *
   * @returns {Promise<Awaited<ReturnType<typeof startTestServer>>>}
   */
  async function bootServer(): Promise<
    Awaited<ReturnType<typeof startTestServer>>
  > {
    return startTestServer({
      backend: await openTempBackend(),
      peerLogFetcher: async ({ url }: { url: string }) =>
        new TextEncoder().encode(servedLog(url))
    })
  }

  /**
   * A client on `baseServerUrl` with a dereferencer of its own, so it reads
   * the log as served now and holds no earlier mapping.
   *
   * @param options {object}
   * @param options.baseServerUrl {string}
   * @param options.signer {ISigner}
   * @param [options.serviceDescription] {ServiceDescription}
   * @param [options.cached] {boolean}   false for a client that reads the
   *   log again on every dereference, as one does once its cache expires
   * @returns {PwsClient}
   */
  function clientOn({
    baseServerUrl,
    signer,
    serviceDescription,
    cached = true
  }: {
    baseServerUrl: string
    signer: ISigner
    serviceDescription?: ServiceDescription
    cached?: boolean
  }): PwsClient {
    const dereferencer = (): ReturnType<typeof createTargetDereferencer> =>
      createTargetDereferencer({
        fetch: async (input: string) => {
          try {
            return new Response(servedLog(input), { status: 200 })
          } catch {
            return new Response('not found', { status: 404 })
          }
        }
      })
    return PwsClient.fromSigner({
      baseServerUrl,
      signer,
      serviceDescription,
      dereferenceTarget: cached
        ? dereferencer()
        : async options => dereferencer()(options)
    })
  }

  beforeAll(async () => {
    one = await bootServer()
    two = await bootServer()
    const signers = await Promise.all(
      [0, 1, 2].map(async () =>
        (await Ed25519VerificationKey.generate()).didKeySigner()
      )
    )
    ;[aliceSigner, bobSigner, carolSigner] = signers as [
      ISigner,
      ISigner,
      ISigner
    ]

    const updateKeyPair = await Ed25519VerificationKey.generate()
    logSigner = webvhLogSigner({ keyPair: updateKeyPair })
    const created = await createDID({
      address: 'https://user.example/accounts/u1',
      signer: logSigner,
      updateKeys: [updateKeyPair.publicKeyMultibase as string],
      vmIdFragment: 'multibase',
      verificationMethods: [
        {
          type: 'Multikey',
          publicKeyMultibase: updateKeyPair.publicKeyMultibase as string,
          purpose: ['authentication']
        }
      ] as never,
      services: [
        pathHandler({
          path: '/',
          serviceEndpoint: `${one.baseServerUrl}space/${spaceId}/`
        })
      ]
    })
    ;({ did, log } = created)
    didUrl = `${did}/`
    logUrl = getFileUrl(did)

    alice = clientOn({ baseServerUrl: one.baseServerUrl, signer: aliceSigner })
    space = alice.space(spaceId, { didUrl })
    await space.configure({
      name: 'Moving Space',
      controller: alice.controllerDid
    })
    await space.collection('photos').configure({ force: true, name: 'Photos' })
    await space.collection('photos').put('doc-1', { photo: 1 })
    await space.collection('albums').configure({ force: true })
    await space.collection('albums').put('a-1', { album: 1 })
  })

  afterAll(async () => {
    await one?.fastify.close()
    await two?.fastify.close()
  })

  it('the server advertises `did-url-targets`', async () => {
    const info = await alice.service()
    expect(
      info.hasFeature({
        spec: AUTHZ_PROFILE_SPEC_ID,
        feature: 'did-url-targets'
      })
    ).toBe(true)
  })

  it('issues a Collection grant the delegate reads and writes under', async () => {
    photosGrant = await space.collection('photos').grant({
      to: bobSigner.id.split('#')[0] as string,
      actions: ['GET', 'PUT'],
      expires
    })
    expect(photosGrant.parentCapability).toBe(rootCapabilityId(didUrl))
    expect(photosGrant.invocationTarget).toBe(`${didUrl}photos/`)

    const bob = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: bobSigner
    })
    const photos = await bob.fromCapability(photosGrant)
    expect(photos).toBeInstanceOf(Collection)
    expect(photos.url).toBe(`${space.url}photos/`)
    expect(await (photos as Collection).get('doc-1')).toEqual({ photo: 1 })
    await (photos as Collection).put('doc-2', { photo: 2 })
    expect(await space.collection('photos').get('doc-2')).toEqual({ photo: 2 })
  })

  it('issues Space and Resource grants in the same form', async () => {
    const bob = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: bobSigner
    })
    const to = bob.controllerDid

    const spaceGrant = await space.grant({ to, actions: ['GET'], expires })
    expect(spaceGrant.parentCapability).toBe(rootCapabilityId(didUrl))
    expect(spaceGrant.invocationTarget).toBe(didUrl)
    const granted = await bob.fromCapability(spaceGrant)
    expect(granted).toBeInstanceOf(Space)
    expect(await (granted as Space).collection('albums').get('a-1')).toEqual({
      album: 1
    })

    const resourceGrant = await space
      .collection('photos')
      .resource('doc-1')
      .grant({ to, actions: ['GET'], expires })
    expect(resourceGrant.parentCapability).toBe(rootCapabilityId(didUrl))
    expect(resourceGrant.invocationTarget).toBe(`${didUrl}photos/doc-1`)
    const resource = await bob.fromCapability(resourceGrant)
    expect(resource).toBeInstanceOf(Resource)
    expect(await (resource as Resource).get()).toEqual({ photo: 1 })
  })

  it('issues an https grant from a handle without `didUrl`', async () => {
    const bob = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: bobSigner
    })
    const plain = alice.space(spaceId)
    const grant = await plain.collection('photos').grant({
      to: bob.controllerDid,
      actions: ['GET'],
      expires
    })
    expect(grant.parentCapability).toBe(rootCapabilityId(plain.url))
    expect(grant.invocationTarget).toBe(`${plain.url}photos/`)
    const photos = (await bob.fromCapability(grant)) as Collection
    expect(await photos.get('doc-1')).toEqual({ photo: 1 })
  })

  it('refuses to issue to a server without the token', async () => {
    const { description } = await alice.service()
    const withoutToken = structuredClone(description)
    for (const entry of withoutToken.specs[AUTHZ_PROFILE_SPEC_ID] ?? []) {
      delete (entry as { features?: string[] }).features
    }
    const client = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: aliceSigner,
      serviceDescription: withoutToken
    })
    const fetchesBefore = logFetches
    const refusal = client
      .space(spaceId, { didUrl })
      .collection('photos')
      .grant({ to: 'did:example:bob', actions: ['GET'] })
    await expect(refusal).rejects.toBeInstanceOf(NotSupportedError)
    await expect(refusal).rejects.toThrow(/did-url-targets/)
    expect(logFetches).toBe(fetchesBefore)
  })

  it('a delegate re-delegates from a handle built on a DID-form grant', async () => {
    const bob = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: bobSigner
    })
    const carol = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: carolSigner
    })
    const photos = (await bob.fromCapability(photosGrant)) as Collection
    const to = carol.controllerDid

    const docGrant = await photos
      .resource('doc-1')
      .grant({ to, actions: ['GET'], expires })
    expect(docGrant.parentCapability).toBe(photosGrant.id)
    expect(docGrant.invocationTarget).toBe(`${didUrl}photos/doc-1`)
    const doc = (await carol.fromCapability(docGrant)) as Resource
    expect(doc.url).toBe(`${space.url}photos/doc-1`)
    expect(await doc.get()).toEqual({ photo: 1 })

    // The Collection handle re-delegates the whole of its own grant, and an
    // explicit https target is translated the same way.
    const collectionGrant = await photos.grant({
      to,
      actions: ['GET'],
      expires
    })
    expect(collectionGrant.invocationTarget).toBe(`${didUrl}photos/`)
    const granted = (await carol.fromCapability(collectionGrant)) as Collection
    expect(await granted.get('doc-1')).toEqual({ photo: 1 })
    const translated = await bob.grant({
      to,
      actions: ['GET'],
      capability: photosGrant,
      target: `${space.url}photos/doc-1`,
      expires
    })
    expect(translated.invocationTarget).toBe(`${didUrl}photos/doc-1`)

    // A target the parent does not cover is refused before signing.
    await expect(
      photos.grant({
        to,
        actions: ['GET'],
        target: `${space.url}albums/`,
        expires
      })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('a delegate whose client is configured for another server re-delegates', async () => {
    // Bob's client is on server two, and its copy of that server's
    // description lacks the token. The Space is on server one, which decides.
    const { description } = await clientOn({
      baseServerUrl: two.baseServerUrl,
      signer: bobSigner
    }).service()
    const withoutToken = structuredClone(description)
    for (const entry of withoutToken.specs[AUTHZ_PROFILE_SPEC_ID] ?? []) {
      delete (entry as { features?: string[] }).features
    }
    const bob = clientOn({
      baseServerUrl: two.baseServerUrl,
      signer: bobSigner,
      serviceDescription: withoutToken
    })
    const carol = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: carolSigner
    })
    const photos = (await bob.fromCapability(photosGrant)) as Collection
    expect(photos.url.startsWith(one.baseServerUrl)).toBe(true)

    const docGrant = await photos
      .resource('doc-1')
      .grant({ to: carol.controllerDid, actions: ['GET'], expires })
    expect(docGrant.invocationTarget).toBe(`${didUrl}photos/doc-1`)
    const doc = (await carol.fromCapability(docGrant)) as Resource
    expect(await doc.get()).toEqual({ photo: 1 })
  })

  it('a chain that mixes the two forms is refused', async () => {
    const bob = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: bobSigner
    })
    const carol = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: carolSigner
    })
    // An https link beneath a DID URL link, which `grant()` never issues:
    // the signer refuses it.
    await expect(
      bob.zcapClient.delegate({
        capability: photosGrant,
        invocationTarget: `${space.url}photos/`,
        controller: carol.controllerDid,
        allowedActions: ['GET', 'PUT'],
        expires
      })
    ).rejects.toThrow(/less restrictive/)

    // An https link beneath the DID URL root, which a handle never issues:
    // the server refuses it.
    const mixed = await alice.zcapClient.delegate({
      capability: rootCapabilityId(didUrl),
      invocationTarget: `${space.url}photos/`,
      controller: carol.controllerDid,
      allowedActions: ['GET', 'PUT'],
      expires
    })
    const photos = (await carol.fromCapability(mixed)) as Collection
    expect(await photos.get('doc-1')).toBeNull()
    await expect(photos.put('doc-8', { photo: 8 })).rejects.toBeInstanceOf(
      NotFoundError
    )
    expect(await space.collection('photos').get('doc-8')).toBeNull()
  })

  it('revokes a DID-form grant at the Space and from the chain', async () => {
    const carol = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: carolSigner
    })
    for (const revoke of [
      // Both submit under the https root of the revocation URL.
      async (zcap: IDelegatedZcap) => space.revoke(zcap),
      // `pws.revoke` dereferences the chain's DID URL root to find the Space.
      async (zcap: IDelegatedZcap) => alice.revoke(zcap)
    ]) {
      const grant = await space.collection('albums').grant({
        to: carol.controllerDid,
        actions: ['GET', 'PUT'],
        expires
      })
      const albums = (await carol.fromCapability(grant)) as Collection
      expect(await albums.get('a-1')).toEqual({ album: 1 })
      await revoke(grant)
      expect(await albums.get('a-1')).toBeNull()
      await expect(albums.put('a-9', { album: 9 })).rejects.toBeInstanceOf(
        NotFoundError
      )
    }
    expect(await space.collection('albums').get('a-9')).toBeNull()
  })

  it('the controller reads and writes through a DID URL', async () => {
    const client = clientOn({
      baseServerUrl: one.baseServerUrl,
      signer: aliceSigner,
      cached: false
    })
    const written = await client.request({
      url: `${didUrl}photos/doc-5`,
      method: 'PUT',
      json: { photo: 5 }
    })
    expect(written.status).toBeLessThan(300)
    const read = await client.request({ url: `${didUrl}photos/doc-5` })
    expect(read.data).toEqual({ photo: 5 })

    const doc = await client.fromDidUrl(`${didUrl}photos/doc-5`, {
      spaceDidUrl: didUrl
    })
    expect(doc).toBeInstanceOf(Resource)
    expect(doc.url).toBe(`${space.url}photos/doc-5`)
    expect(await (doc as Resource).get()).toEqual({ photo: 5 })

    const opened = await client.fromDidUrl(didUrl)
    expect(opened).toBeInstanceOf(Space)
    expect(opened.url).toBe(space.url)
    const photos = (opened as Space).collection('photos')
    await photos.put('doc-6', { photo: 6 })
    expect(await space.collection('photos').get('doc-6')).toEqual({ photo: 6 })

    // The handle issues its grants in DID URL form.
    const grant = await photos.grant({
      to: bobSigner.id.split('#')[0] as string,
      actions: ['GET'],
      expires
    })
    expect(grant.parentCapability).toBe(rootCapabilityId(didUrl))
    expect(grant.invocationTarget).toBe(`${didUrl}photos/`)

    openedBeforeMove = (await client.fromDidUrl(`${didUrl}photos/`, {
      spaceDidUrl: didUrl
    })) as Collection
    expect(await openedBeforeMove.get('doc-1')).toEqual({ photo: 1 })
  })

  it('the unchanged grant works after the Space moves to a second server', async () => {
    const aliceOnTwo = clientOn({
      baseServerUrl: two.baseServerUrl,
      signer: aliceSigner
    })
    const moved = aliceOnTwo.space(spaceId)
    await moved.configure({
      name: 'Moving Space',
      controller: aliceOnTwo.controllerDid
    })
    await moved.import(await space.exportBlob())

    const updated = await updateDID({
      log,
      signer: logSigner,
      services: [pathHandler({ path: '/', serviceEndpoint: moved.url })]
    })
    log = updated.log

    const bob = clientOn({
      baseServerUrl: two.baseServerUrl,
      signer: bobSigner
    })
    const photos = await bob.fromCapability(photosGrant)
    expect(photos.url).toBe(`${moved.url}photos/`)
    expect(await (photos as Collection).get('doc-1')).toEqual({ photo: 1 })
    await (photos as Collection).put('doc-3', { photo: 3 })
    expect(await moved.collection('photos').get('doc-3')).toEqual({ photo: 3 })
    // The write went to the second server alone.
    expect(await space.collection('photos').get('doc-3')).toBeNull()

    // The controller issues from the same `didUrl` at the Space's new home.
    const grant = await aliceOnTwo
      .space(spaceId, { didUrl })
      .collection('albums')
      .grant({ to: bob.controllerDid, actions: ['GET'], expires })
    expect(grant.parentCapability).toBe(rootCapabilityId(didUrl))
    const albums = (await bob.fromCapability(grant)) as Collection
    expect(await albums.get('a-1')).toEqual({ album: 1 })
  })

  it('a handle opened on a DID URL before the move is refused after it', async () => {
    const read = openedBeforeMove.get('doc-1')
    await expect(read).rejects.toBeInstanceOf(TargetDereferenceError)
    await expect(read).rejects.toThrow(/fromDidUrl\(\)/)
    await expect(
      openedBeforeMove.resource('doc-1').delete()
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    // Nothing was deleted at the old location.
    expect(await space.collection('photos').get('doc-1')).toEqual({ photo: 1 })

    const reopened = (await clientOn({
      baseServerUrl: two.baseServerUrl,
      signer: aliceSigner
    }).fromDidUrl(`${didUrl}photos/`, { spaceDidUrl: didUrl })) as Collection
    expect(reopened.url.startsWith(two.baseServerUrl)).toBe(true)
    expect(await reopened.get('doc-1')).toEqual({ photo: 1 })
  })
})
