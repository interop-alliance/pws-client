/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `./did-url` entry and the `dereferenceTarget` option of `PwsClient`.
 *
 * The first suite drives `createTargetDereferencer` over a stubbed `fetch`
 * that serves the history log of a `did:webvh` minted for the test. It covers
 * the dereference, the cache and its lifetime, a version selector, and the
 * refusals.
 *
 * The second suite sends a request through a real ezcap `ZcapClient` under a
 * capability whose target is a DID URL. The global `fetch` is stubbed, so it
 * stands in for both the server and the host of the DID log. It covers the
 * built-in dereferencer the client loads on first use, a caller's override,
 * and an https capability, which never calls the hook.
 *
 * The third suite covers a delegate holding a grant in DID URL form:
 * `fromCapability`, the request URL check of the handles, and the Collection
 * Metadata write guard.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import {
  createDID,
  getFileUrl,
  logToJsonlString,
  signerFromExternalKey,
  updateDID
} from '@interop/did-method-webvh'
import type { DIDLog, ServiceEndpoint } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import {
  Collection,
  NotFoundError,
  PwsClient,
  Resource,
  Space,
  SpaceGrantRequiredError
} from '../../src/index.js'
import type { ISigner, IZcap } from '../../src/index.js'
import {
  TARGET_CACHE_TTL,
  TargetDereferenceError,
  createTargetDereferencer
} from '../../src/did-url.js'
import { rootCapabilityId } from '../../src/paths/index.js'
import {
  STUB_ORIGIN,
  baseServerUrlFor,
  requestUrl,
  serviceDescriptionFor,
  spaceUrlFor
} from '../helpers/stubClient.js'
import { pathHandler } from '../helpers/pathHandler.js'

const SPACE_URL = spaceUrlFor('s1')
const MOVED_SPACE_URL = 'https://other.example/space/s1/'

/**
 * Mints a `did:webvh` whose document carries the given services.
 *
 * @param options {object}
 * @param options.address {string}   the https address the DID is anchored at
 * @param options.services {ServiceEndpoint[]}
 * @returns {Promise<object>} { did, log, update }, where `update` appends a
 *   version with other services and resolves to the longer log
 */
async function mintDid({
  address,
  services
}: {
  address: string
  services: ServiceEndpoint[]
}): Promise<{
  did: string
  log: DIDLog
  update: (options: { services: ServiceEndpoint[] }) => Promise<DIDLog>
}> {
  const keyPair = await Ed25519VerificationKey.generate()
  const keySigner = keyPair.didKeySigner()
  const publicKeyMultibase = keyPair.publicKeyMultibase as string
  const shared = {
    signer: signerFromExternalKey({
      publicKeyMultibase,
      sign: async ({ data }: { data: Uint8Array }) =>
        await keySigner.sign({ data })
    }),
    updateKeys: [publicKeyMultibase],
    verificationMethods: [
      {
        type: 'Multikey',
        publicKeyMultibase,
        purpose: ['authentication' as const]
      }
    ]
  }
  const created = await createDID({ ...shared, address, services })
  return {
    did: created.did,
    log: created.log,
    async update({ services: nextServices }) {
      const updated = await updateDID({
        ...shared,
        log: created.log,
        services: nextServices
      })
      return updated.log
    }
  }
}

/**
 * The DID under test, and the two versions of its log. Version 1 maps `/` to
 * the Space on the stub server. Version 2 maps it to the Space's copy on
 * another host, as a move does.
 */
let did: string
let logUrl: string
let firstLog: DIDLog
let secondLog: DIDLog

beforeAll(async () => {
  const minted = await mintDid({
    address: 'https://alice.example',
    services: [pathHandler({ path: '/', serviceEndpoint: SPACE_URL })]
  })
  did = minted.did
  logUrl = getFileUrl(did)
  firstLog = minted.log
  secondLog = await minted.update({
    services: [pathHandler({ path: '/', serviceEndpoint: MOVED_SPACE_URL })]
  })
})

/**
 * A stub `fetch` that serves the DID log, and counts how often it is asked.
 * `log` is read on every call, so a test can swap it.
 *
 * @returns {object} { fetch, served, calls }
 */
function logHost(): {
  fetch: (input: string) => Promise<Response>
  served: { log: DIDLog | undefined }
  calls: string[]
} {
  const served: { log: DIDLog | undefined } = { log: firstLog }
  const calls: string[] = []
  return {
    served,
    calls,
    async fetch(input: string): Promise<Response> {
      calls.push(input)
      if (input !== logUrl || served.log === undefined) {
        return new Response('not found', { status: 404 })
      }
      return new Response(logToJsonlString(served.log), { status: 200 })
    }
  }
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('createTargetDereferencer', () => {
  it('maps a DID URL through the matching PathHandler', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    await expect(
      dereferenceTarget({ invocationTarget: `${did}/photos/cat.jpg` })
    ).resolves.toBe(`${SPACE_URL}photos/cat.jpg`)
    await expect(
      dereferenceTarget({ invocationTarget: `${did}/` })
    ).resolves.toBe(SPACE_URL)
  })

  it('returns a target that is not a DID URL as it is, with no fetch', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    await expect(
      dereferenceTarget({ invocationTarget: `${SPACE_URL}photos/` })
    ).resolves.toBe(`${SPACE_URL}photos/`)
    expect(host.calls).toEqual([])
  })

  it('serves a repeated target from its cache', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    const invocationTarget = `${did}/photos/`
    const [first, second] = await Promise.all([
      dereferenceTarget({ invocationTarget }),
      dereferenceTarget({ invocationTarget })
    ])
    expect(first).toBe(`${SPACE_URL}photos/`)
    expect(second).toBe(first)
    await dereferenceTarget({ invocationTarget })
    expect(host.calls).toEqual([logUrl])
  })

  it('reads the document again once the cache lifetime has passed', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    const invocationTarget = `${did}/photos/`
    const start = Date.now()
    const now = vi.spyOn(Date, 'now').mockReturnValue(start)
    await dereferenceTarget({ invocationTarget })

    host.served.log = secondLog
    now.mockReturnValue(start + TARGET_CACHE_TTL - 1)
    await expect(dereferenceTarget({ invocationTarget })).resolves.toBe(
      `${SPACE_URL}photos/`
    )
    now.mockReturnValue(start + TARGET_CACHE_TTL)
    await expect(dereferenceTarget({ invocationTarget })).resolves.toBe(
      `${MOVED_SPACE_URL}photos/`
    )
    expect(host.calls).toEqual([logUrl, logUrl])
  })

  it('keeps one cache per dereferencer', async () => {
    const host = logHost()
    const invocationTarget = `${did}/photos/`
    await createTargetDereferencer({ fetch: host.fetch })({ invocationTarget })
    await createTargetDereferencer({ fetch: host.fetch })({ invocationTarget })
    expect(host.calls).toEqual([logUrl, logUrl])
  })

  it('dereferences a pinned target through the version it names', async () => {
    const host = logHost()
    host.served.log = secondLog
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    await expect(
      dereferenceTarget({ invocationTarget: `${did}/photos/` })
    ).resolves.toBe(`${MOVED_SPACE_URL}photos/`)
    await expect(
      dereferenceTarget({ invocationTarget: `${did}/photos/?versionNumber=1` })
    ).resolves.toBe(`${SPACE_URL}photos/`)
    const versionId = secondLog[0]?.versionId as string
    await expect(
      dereferenceTarget({
        invocationTarget: `${did}/photos/?versionId=${versionId}`
      })
    ).resolves.toBe(`${SPACE_URL}photos/`)
  })

  it('refuses a target with a fragment', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    for (const invocationTarget of [
      `${did}/photos/#key-1`,
      `${did}/photos/#`
    ]) {
      const refusal = dereferenceTarget({ invocationTarget })
      await expect(refusal).rejects.toBeInstanceOf(TargetDereferenceError)
      await expect(refusal).rejects.toThrow(/fragment/)
    }
    expect(host.calls).toEqual([])
  })

  it('refuses a target no PathHandler matches', async () => {
    const created = await mintDid({
      address: 'https://bob.example',
      services: [pathHandler({ path: '/photos', serviceEndpoint: SPACE_URL })]
    })
    const dereferenceTarget = createTargetDereferencer({
      fetch: async () =>
        new Response(logToJsonlString(created.log), { status: 200 })
    })
    const refusal = dereferenceTarget({
      invocationTarget: `${created.did}/albums/`
    })
    await expect(refusal).rejects.toBeInstanceOf(TargetDereferenceError)
    await expect(refusal).rejects.toThrow(/No PathHandler/)
    await expect(refusal).rejects.toMatchObject({
      name: 'TargetDereferenceError',
      cause: expect.any(Error)
    })
  })

  it('refuses a result that is not an https URL in canonical form', async () => {
    const created = await mintDid({
      address: 'https://carol.example',
      services: [
        pathHandler({ path: '/', serviceEndpoint: SPACE_URL }),
        pathHandler({
          path: '/plain',
          serviceEndpoint: 'http://other.example/space/s1/'
        }),
        pathHandler({
          path: '/upper',
          serviceEndpoint: 'https://PWS.example/space/s1/'
        })
      ]
    })
    const dereferenceTarget = createTargetDereferencer({
      fetch: async () =>
        new Response(logToJsonlString(created.log), { status: 200 })
    })
    for (const path of [
      '/plain/photos/',
      '/upper/photos/',
      '/photos/../private/',
      '/photos/%2e%2e/private/',
      '/photos\\private/'
    ]) {
      await expect(
        dereferenceTarget({ invocationTarget: `${created.did}${path}` })
      ).rejects.toBeInstanceOf(TargetDereferenceError)
    }
    await expect(
      dereferenceTarget({ invocationTarget: `${created.did}/photos/` })
    ).resolves.toBe(`${SPACE_URL}photos/`)
  })

  it('refuses a malformed target before any fetch', async () => {
    const host = logHost()
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    await expect(
      dereferenceTarget({ invocationTarget: did })
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    await expect(
      dereferenceTarget({ invocationTarget: 'did:web:alice.example/photos/' })
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    await expect(
      dereferenceTarget({ invocationTarget: `${did}/photos/?service=files` })
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    expect(host.calls).toEqual([])
  })

  it('does not cache a failure', async () => {
    const host = logHost()
    host.served.log = undefined
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    const invocationTarget = `${did}/photos/`
    await expect(
      dereferenceTarget({ invocationTarget })
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    host.served.log = firstLog
    await expect(dereferenceTarget({ invocationTarget })).resolves.toBe(
      `${SPACE_URL}photos/`
    )
  })

  it('counts the cache lifetime from the dereference that succeeded', async () => {
    const host = logHost()
    host.served.log = undefined
    const dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    const invocationTarget = `${did}/photos/`
    const start = Date.now()
    const now = vi.spyOn(Date, 'now').mockReturnValue(start)
    await expect(
      dereferenceTarget({ invocationTarget })
    ).rejects.toBeInstanceOf(TargetDereferenceError)

    host.served.log = firstLog
    now.mockReturnValue(start + TARGET_CACHE_TTL - 1)
    await dereferenceTarget({ invocationTarget })

    host.served.log = secondLog
    now.mockReturnValue(start + TARGET_CACHE_TTL + 1)
    await expect(dereferenceTarget({ invocationTarget })).resolves.toBe(
      `${SPACE_URL}photos/`
    )
  })
})

describe('PwsClient dereferenceTarget', () => {
  const resourceUrl = `${SPACE_URL}photos/doc-1`

  /**
   * Stubs the global `fetch` as the server and the DID log host in one, and
   * records every request.
   *
   * @returns {Request[]}   the requests seen, in order
   */
  function stubNetwork(): Request[] {
    const requests: Request[] = []
    vi.stubGlobal(
      'fetch',
      async (input: string | Request, init?: RequestInit) => {
        const request =
          typeof input === 'string' ? new Request(input, init) : input
        requests.push(request)
        if (requestUrl(input) === logUrl) {
          return new Response(logToJsonlString(firstLog), { status: 200 })
        }
        if (requestUrl(input).startsWith(STUB_ORIGIN)) {
          return new Response(JSON.stringify({ photo: 1 }), {
            status: 200,
            headers: { 'content-type': 'application/json' }
          })
        }
        return new Response('not found', { status: 404 })
      }
    )
    return requests
  }

  /**
   * A signer and the root capability of the Space under its DID URL.
   *
   * @returns {Promise<{ signer: ISigner; capability: IZcap }>}
   */
  async function didUrlRoot(): Promise<{ signer: ISigner; capability: IZcap }> {
    const keyPair = await Ed25519VerificationKey.generate()
    const signer = keyPair.didKeySigner() as ISigner
    const invocationTarget = `${did}/`
    const capability = {
      '@context': 'https://w3id.org/zcap/v1',
      id: rootCapabilityId(invocationTarget),
      controller: (signer.id as string).split('#')[0] as string,
      invocationTarget
    } as IZcap
    return { signer, capability }
  }

  it('loads the built-in dereferencer once, on the first DID URL target', async () => {
    const requests = stubNetwork()
    const { signer, capability } = await didUrlRoot()
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer,
      serviceDescription: serviceDescriptionFor()
    })

    const response = await pws.request({ url: resourceUrl, capability })
    expect(response.data).toEqual({ photo: 1 })
    await pws.request({ url: resourceUrl, capability })

    const urls = requests.map(request => request.url)
    expect(urls).toEqual([logUrl, resourceUrl, resourceUrl])
    const sent = requests[1] as Request
    expect(sent.headers.get('capability-invocation')).toContain(
      encodeURIComponent(`${did}/`)
    )
    expect(sent.headers.get('authorization')).toMatch(/^Signature /)
  })

  it('refuses a request outside the dereferenced target', async () => {
    stubNetwork()
    const { signer, capability } = await didUrlRoot()
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer,
      serviceDescription: serviceDescriptionFor()
    })
    await expect(
      pws.request({ url: spaceUrlFor('s2'), capability })
    ).rejects.toThrow(/dereferenced to/)
  })

  it('calls a caller-supplied dereferenceTarget instead', async () => {
    const requests = stubNetwork()
    const { signer, capability } = await didUrlRoot()
    const dereferenceTarget = vi.fn(async () => SPACE_URL)
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget
    })

    await pws.request({ url: resourceUrl, capability })
    expect(dereferenceTarget).toHaveBeenCalledWith({
      invocationTarget: `${did}/`
    })
    expect(requests.map(request => request.url)).toEqual([resourceUrl])
  })

  it('does not call the hook for an https capability', async () => {
    const requests = stubNetwork()
    const { signer } = await didUrlRoot()
    const dereferenceTarget = vi.fn(async () => SPACE_URL)
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget
    })
    await pws.spaceAt(SPACE_URL).collection('photos').get('doc-1')
    expect(dereferenceTarget).not.toHaveBeenCalled()
    expect(requests.map(request => request.url)).toEqual([resourceUrl])
  })

  it('passes the option through forSpace and the constructor', async () => {
    stubNetwork()
    const { signer, capability } = await didUrlRoot()
    const dereferenceTarget = vi.fn(async () => SPACE_URL)
    const pws = PwsClient.forSpace({
      spaceUrl: SPACE_URL,
      signer,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget
    })
    await pws.request({ url: resourceUrl, capability })
    expect(dereferenceTarget).toHaveBeenCalledTimes(1)
  })
})

describe('a delegate holding a DID-form grant', () => {
  const resourceUrl = `${SPACE_URL}photos/doc-1`
  let ownerSigner: ISigner
  let bobSigner: ISigner
  let dereferenceTarget: ReturnType<typeof createTargetDereferencer>
  let logFetches: string[]

  beforeAll(async () => {
    ownerSigner = (
      await Ed25519VerificationKey.generate()
    ).didKeySigner() as ISigner
    bobSigner = (
      await Ed25519VerificationKey.generate()
    ).didKeySigner() as ISigner
  })

  /**
   * Stubs the global `fetch` as the server, and gives the delegate a
   * dereferencer over a separate stub that serves the DID log.
   *
   * @returns {Request[]}   the requests the server saw, in order
   */
  function stubServer(): Request[] {
    const host = logHost()
    logFetches = host.calls
    dereferenceTarget = createTargetDereferencer({ fetch: host.fetch })
    const requests: Request[] = []
    vi.stubGlobal(
      'fetch',
      async (input: string | Request, init?: RequestInit) => {
        requests.push(
          typeof input === 'string' ? new Request(input, init) : input
        )
        return new Response(JSON.stringify({ photo: 1 }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
      }
    )
    return requests
  }

  /**
   * The delegate's client.
   *
   * @returns {PwsClient}
   */
  function bobClient(): PwsClient {
    return PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer: bobSigner,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget
    })
  }

  /**
   * A grant to the delegate, signed by the owner.
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
    const owner = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer: ownerSigner
    })
    return owner.zcapClient.delegate({
      capability: rootCapabilityId(root),
      invocationTarget: target,
      controller: (bobSigner.id as string).split('#')[0] as string,
      allowedActions: ['GET', 'PUT'],
      expires: new Date(Date.now() + 60 * 60 * 1000)
    })
  }

  it('resolves an https grant with no fetch', async () => {
    const requests = stubServer()
    const zcap = await grant({ root: SPACE_URL, target: `${SPACE_URL}photos/` })
    const handle = await bobClient().fromCapability(zcap)
    expect(handle).toBeInstanceOf(Collection)
    expect(handle.url).toBe(`${SPACE_URL}photos/`)
    expect(logFetches).toEqual([])
    expect(requests).toEqual([])
  })

  it('finds the Space and the handle of a DID-form grant by dereferencing', async () => {
    const requests = stubServer()
    const pws = bobClient()
    const collection = await pws.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/` })
    )
    expect(collection).toBeInstanceOf(Collection)
    expect(collection.url).toBe(`${SPACE_URL}photos/`)
    expect((collection as Collection).spaceUrl).toBe(SPACE_URL)

    const resource = await pws.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/doc-1` })
    )
    expect(resource).toBeInstanceOf(Resource)
    expect(resource.url).toBe(resourceUrl)

    const space = await pws.fromCapability(
      await grant({ root: `${did}/`, target: `${did}/` })
    )
    expect(space).toBeInstanceOf(Space)
    expect(space.url).toBe(SPACE_URL)
    // Only the DID log was fetched, and nothing was sent to the server.
    expect(new Set(logFetches)).toEqual(new Set([logUrl]))
    expect(requests).toEqual([])
  })

  it('sends a handle request to the dereferenced URL under the DID-form grant', async () => {
    const requests = stubServer()
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const collection = (await bobClient().fromCapability(zcap)) as Collection
    await expect(collection.get('doc-1')).resolves.toEqual({ photo: 1 })
    expect(requests.map(request => request.url)).toEqual([resourceUrl])
    expect(requests[0]?.headers.get('capability-invocation')).toContain(
      'capability="'
    )
  })

  it('answers a request outside the dereferenced target without sending', async () => {
    const requests = stubServer()
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const albums = bobClient()
      .spaceAt(SPACE_URL)
      .collection('albums', { capability: zcap })
    await expect(albums.get('a-1')).resolves.toBeNull()
    await expect(albums.put('a-1', { album: 1 })).rejects.toThrow(
      /lies outside the capability's invocation target/
    )
    expect(requests).toEqual([])
  })

  it('reports a handle the Space has moved away from, on a read and a delete', async () => {
    const requests = stubServer()
    const host = logHost()
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer: bobSigner,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget: createTargetDereferencer({ fetch: host.fetch })
    })
    const start = Date.now()
    const now = vi.spyOn(Date, 'now').mockReturnValue(start)
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const collection = (await pws.fromCapability(zcap)) as Collection
    await expect(collection.get('doc-1')).resolves.toEqual({ photo: 1 })

    // The `PathHandler` is repointed, and the cached mapping expires.
    host.served.log = secondLog
    now.mockReturnValue(start + TARGET_CACHE_TTL)
    // Each request starts only once the one before it has settled.
    for (const request of [
      async () => collection.get('doc-1'),
      async () => collection.resource('doc-1').delete(),
      async () => collection.resource('doc-1').get(),
      async () => collection.put('doc-1', { photo: 2 })
    ]) {
      const refusal = await request().catch((err: unknown) => err)
      expect(refusal).toBeInstanceOf(TargetDereferenceError)
      expect((refusal as Error).message).toMatch(/fromCapability\(\)/)
    }
    expect(requests.map(request => request.url)).toEqual([resourceUrl])

    // A handle built again addresses the new location.
    const moved = await pws.fromCapability(zcap)
    expect(moved.url).toBe(`${MOVED_SPACE_URL}photos/`)
  })

  /**
   * The delegate's client over a hook that reads a table the test edits.
   *
   * @param table {Record<string, string>}   the URL each DID URL names
   * @returns {object} { pws, calls }, where `calls` lists the DID URLs the
   *   hook was asked for, in order
   */
  function tableClient(table: Record<string, string>): {
    pws: PwsClient
    calls: string[]
  } {
    const calls: string[] = []
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer: bobSigner,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget: async ({ invocationTarget }) => {
        calls.push(invocationTarget)
        return table[invocationTarget] as string
      }
    })
    return { pws, calls }
  }

  it('reports a moved Space while the root answer is still the old one', async () => {
    const requests = stubServer()
    const table = {
      [`${did}/`]: SPACE_URL,
      [`${did}/photos/`]: `${SPACE_URL}photos/`
    }
    const { pws } = tableClient(table)
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const collection = (await pws.fromCapability(zcap)) as Collection

    // Only the target's answer has caught up with the move.
    table[`${did}/photos/`] = `${MOVED_SPACE_URL}photos/`
    await expect(collection.get('doc-1')).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
    await expect(collection.resource('doc-1').delete()).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
    expect(requests).toEqual([])
  })

  it('reports a target the DID document maps to another Space', async () => {
    const requests = stubServer()
    const table = {
      [`${did}/`]: SPACE_URL,
      [`${did}/photos/`]: `${SPACE_URL}photos/`
    }
    const { pws } = tableClient(table)
    const zcap = await grant({ root: `${did}/`, target: `${did}/photos/` })
    const collection = (await pws.fromCapability(zcap)) as Collection

    // A longer `PathHandler` now maps the granted path, and the root stays.
    table[`${did}/photos/`] = 'https://other.example/space/s2/photos/'
    const refusal = await collection.get('doc-1').catch((err: unknown) => err)
    expect(refusal).toBeInstanceOf(TargetDereferenceError)
    expect((refusal as Error).message).toMatch(/its root .* dereferences to/)
    expect(requests).toEqual([])
  })

  it('reports a moved Space on a Collection Metadata write of a Space grant', async () => {
    const requests = stubServer()
    const table = { [`${did}/`]: SPACE_URL }
    const { pws, calls } = tableClient(table)
    const zcap = await grant({ root: `${did}/`, target: `${did}/` })
    const space = (await pws.fromCapability(zcap)) as Space

    table[`${did}/`] = MOVED_SPACE_URL
    calls.length = 0
    await expect(
      space.collection('photos').setName('Photos')
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    // The grant's target is its root, which is dereferenced once.
    expect(calls).toEqual([`${did}/`])

    calls.length = 0
    await expect(
      space.collection('photos').get('doc-1')
    ).rejects.toBeInstanceOf(TargetDereferenceError)
    expect(calls).toEqual([`${did}/`])
    expect(requests).toEqual([])
  })

  it('reports a target that does not dereference, even on a read', async () => {
    stubServer()
    const pws = bobClient()
    const unmapped = await grant({
      root: `${did}/`,
      target: 'did:web:alice.example/photos/'
    })
    await expect(pws.fromCapability(unmapped)).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
    const photos = pws
      .spaceAt(SPACE_URL)
      .collection('photos', { capability: unmapped })
    await expect(photos.get('doc-1')).rejects.toBeInstanceOf(
      TargetDereferenceError
    )
  })

  it('wraps a failure of a caller-supplied hook', async () => {
    stubServer()
    // A `PwsError` of the hook is wrapped too: left as it is, its 404 status
    // would read as an absent resource.
    for (const cause of [
      new Error('resolver offline'),
      new NotFoundError('no such DID log', { status: 404 })
    ]) {
      const pws = PwsClient.fromSigner({
        baseServerUrl: baseServerUrlFor(),
        signer: bobSigner,
        serviceDescription: serviceDescriptionFor(),
        dereferenceTarget: async () => {
          throw cause
        }
      })
      const refusal = await pws
        .fromCapability(
          await grant({ root: `${did}/`, target: `${did}/photos/` })
        )
        .catch((err: unknown) => err)
      expect(refusal).toBeInstanceOf(TargetDereferenceError)
      expect((refusal as Error).cause).toBe(cause)
    }
  })

  it('refuses a DID-form grant whose target lies outside its root', async () => {
    stubServer()
    const pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrlFor(),
      signer: bobSigner,
      serviceDescription: serviceDescriptionFor(),
      dereferenceTarget: async ({ invocationTarget }) =>
        invocationTarget.endsWith('/elsewhere/') ? spaceUrlFor('s2') : SPACE_URL
    })
    await expect(
      pws.fromCapability(
        await grant({ root: `${did}/`, target: `${did}/elsewhere/` })
      )
    ).rejects.toThrow(/not address anything at or beneath the Space/)
  })

  it('builds a handle for a chain that mixes the two forms, and sends', async () => {
    const requests = stubServer()
    const pws = bobClient()
    for (const mixed of [
      { root: SPACE_URL, target: `${did}/photos/` },
      { root: `${did}/`, target: `${SPACE_URL}photos/` }
    ]) {
      const collection = (await pws.fromCapability(
        await grant(mixed)
      )) as Collection
      expect(collection.url).toBe(`${SPACE_URL}photos/`)
      await collection.get('doc-1')
    }
    // The server is the one that refuses a mixed chain.
    expect(requests.map(request => request.url)).toEqual([
      resourceUrl,
      resourceUrl
    ])
  })

  it('admits a Collection Metadata write under a DID-form Space grant', async () => {
    const requests = stubServer()
    const space = (await bobClient().fromCapability(
      await grant({ root: `${did}/`, target: `${did}/` })
    )) as Space
    // The stub serves no validator, so the write fails later. What matters
    // is that it got past the guard and reached the server.
    const outcome = await space
      .collection('photos')
      .setName('Renamed')
      .catch((err: unknown) => err)
    expect(outcome).not.toBeInstanceOf(SpaceGrantRequiredError)
    expect(requests.map(request => request.url)).toContain(
      `${SPACE_URL}photos/meta`
    )
  })

  it('refuses that write under a DID-form Collection grant', async () => {
    const requests = stubServer()
    const collection = (await bobClient().fromCapability(
      await grant({ root: `${did}/`, target: `${did}/photos/` })
    )) as Collection
    await expect(collection.setName('Renamed')).rejects.toBeInstanceOf(
      SpaceGrantRequiredError
    )
    expect(requests).toEqual([])
  })
})
