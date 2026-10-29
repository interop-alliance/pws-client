/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the lazy navigational handles and capability-rebuilding. A
 * `WasClient` over a stub `ZcapClient` builds `Space`/`Collection`/`Resource`
 * handles synchronously, with no network or key material, each one's URL
 * derived from the Space URL it was opened on. `fromCapability` reads the
 * Space off a zcap's delegation chain and derives a handle at the depth its
 * `invocationTarget` addresses beneath that Space.
 */
import { describe, it, expect } from 'vitest'

import {
  WasClient,
  Space,
  Collection,
  Resource,
  ValidationError,
  AuthRequiredError,
  NotSupportedError,
  WasServerError
} from '../../src/index.js'
import type { IDID, IZcap } from '../../src/index.js'
import { rootCapabilityId } from '../../src/paths.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import {
  clientWithRequestSpy,
  clientWithStub,
  jsonResponse,
  serviceDescriptionFor,
  baseServerUrlFor,
  spaceUrlFor
} from '../helpers/stubClient.js'

/**
 * Builds a `WasClient` over a minimal stub `ZcapClient` -- enough to construct
 * handles and derive `controllerDid`, without a signer or server.
 *
 * @param [signerId] {string}   the invocationSigner id (DID + key fragment)
 * @returns {WasClient}
 */
function stubClient(signerId = 'did:example:alice#key-1'): WasClient {
  const zcapClient = {
    invocationSigner: { id: signerId }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({
    baseServerUrl: baseServerUrlFor(),
    zcapClient,
    serviceDescription: serviceDescriptionFor()
  })
}

describe('lazy handles', () => {
  it('builds the space/collection/resource chain synchronously, no I/O', () => {
    const client = stubClient()
    const space = client.spaceAt(spaceUrlFor('does-not-exist'))
    expect(space).toBeInstanceOf(Space)

    const collection = space.collection('nope')
    expect(collection).toBeInstanceOf(Collection)

    const resource = collection.resource('whatever')
    expect(resource).toBeInstanceOf(Resource)
    expect(resource.collectionId).toBe('nope')
    expect(resource.id).toBe('whatever')
  })

  it('derives every handle URL from the Space URL', () => {
    const space = stubClient().spaceAt('https://was.example/space/s/')
    expect(space.url).toBe('https://was.example/space/s/')
    expect(space.id).toBe('s')

    const collection = space.collection('c')
    expect(collection.spaceUrl).toBe('https://was.example/space/s/')
    expect(collection.id).toBe('c')
    expect(collection.url).toBe('https://was.example/space/s/c/')

    const resource = collection.resource('r')
    expect(resource.spaceUrl).toBe('https://was.example/space/s/')
    expect(resource.collectionId).toBe('c')
    expect(resource.id).toBe('r')
    expect(resource.url).toBe('https://was.example/space/s/c/r')
  })

  it('percent-encodes ids into handle URLs and decodes the Space id', () => {
    const space = stubClient().spaceAt('https://was.example/space/a%20b/')
    expect(space.id).toBe('a b')
    const collection = space.collection('c/d')
    expect(collection.url).toBe('https://was.example/space/a%20b/c%2Fd/')
    const resource = collection.resource('r#1')
    expect(resource.url).toBe('https://was.example/space/a%20b/c%2Fd/r%231')
  })

  it('spaceAt canonicalizes the Space URL', () => {
    const client = stubClient()
    for (const spaceUrl of [
      'https://was.example/space/s',
      'https://was.example/space/s///',
      'https://WAS.Example:443/space/s/'
    ]) {
      const space = client.spaceAt(spaceUrl)
      expect(space.url).toBe('https://was.example/space/s/')
      expect(space.collection('c').url).toBe('https://was.example/space/s/c/')
    }
  })

  it('rejects a Space URL whose id is a malformed percent escape at construction', () => {
    const client = stubClient()
    expect(() => client.spaceAt('https://was.example/space/%ff/')).toThrow(
      ValidationError
    )
    expect(() =>
      client.fromCapability({
        id: 'urn:uuid:child',
        parentCapability: rootCapabilityId('https://was.example/space/%ff/'),
        invocationTarget: 'https://was.example/space/%ff/c/'
      } as unknown as IZcap)
    ).toThrow(ValidationError)
    // Every handle beneath such a Space refuses it too, not only the Space
    // handle that decodes the id.
    expect(() =>
      client.collectionAt('https://was.example/space/%ff/c/')
    ).toThrow(ValidationError)
  })

  it('spaceAt rejects a URL that is not a Space URL', () => {
    const client = stubClient()
    for (const spaceUrl of [
      'https://was.example/space/s/?q=1',
      'ftp://was.example/space/s/',
      '/space/s/',
      's'
    ]) {
      expect(() => client.spaceAt(spaceUrl)).toThrow(ValidationError)
    }
  })

  it('derives controllerDid from the signer id (drops the key fragment)', () => {
    expect(stubClient('did:example:alice#key-1').controllerDid).toBe(
      'did:example:alice'
    )
  })

  it('throws if the wrapped client has no invocationSigner id', () => {
    const zcapClient = {
      invocationSigner: {}
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      baseServerUrl: baseServerUrlFor(),
      serviceDescription: serviceDescriptionFor(),
      zcapClient
    })
    expect(() => client.controllerDid).toThrow(ValidationError)
  })
})

describe('fromCapability', () => {
  const client = stubClient()
  const spaceUrl = spaceUrlFor('s')

  /**
   * A single-level delegated capability rooted in the Space at `root`, with
   * the given `invocationTarget`.
   *
   * @param invocationTarget {string}
   * @param [root] {string}   the Space URL the chain roots at
   * @returns {IZcap}
   */
  function zcapFor(invocationTarget: string, root = spaceUrl): IZcap {
    return {
      id: 'urn:uuid:child',
      parentCapability: rootCapabilityId(root),
      invocationTarget
    } as unknown as IZcap
  }

  it('rebuilds a Space handle from a space-scoped invocationTarget', () => {
    const handle = client.fromCapability(
      zcapFor('https://was.example/space/s/')
    )
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).id).toBe('s')
    expect((handle as Space).url).toBe(spaceUrl)
  })

  it('reads the bare Space form as the Space', () => {
    const handle = client.fromCapability(zcapFor('https://was.example/space/s'))
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).url).toBe(spaceUrl)
  })

  it('rebuilds a Collection handle from a collection-scoped target', () => {
    const handle = client.fromCapability(
      zcapFor('https://was.example/space/s/c')
    )
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).id).toBe('c')
    expect((handle as Collection).spaceUrl).toBe(spaceUrl)
    expect((handle as Collection).url).toBe('https://was.example/space/s/c/')
  })

  it('rebuilds a Resource handle from a resource-scoped target', () => {
    const handle = client.fromCapability(
      zcapFor('https://was.example/space/s/c/r')
    )
    expect(handle).toBeInstanceOf(Resource)
    expect((handle as Resource).collectionId).toBe('c')
    expect((handle as Resource).id).toBe('r')
    expect((handle as Resource).spaceUrl).toBe(spaceUrl)
    expect((handle as Resource).url).toBe('https://was.example/space/s/c/r')
  })

  it('throws for an invocationTarget outside the Space the chain roots at', () => {
    for (const target of [
      'https://was.example/other/x',
      'https://was.example/space/s2/c/',
      'https://elsewhere.example/space/s/c/'
    ]) {
      expect(() => client.fromCapability(zcapFor(target))).toThrow(
        /not address anything at or beneath the Space/
      )
    }
  })

  it('reads the Space off proof.capabilityChain in a multi-level chain', () => {
    const handle = client.fromCapability({
      id: 'urn:uuid:grandchild',
      parentCapability: 'urn:uuid:child',
      invocationTarget: 'https://was.example/space/s/c/r',
      proof: { capabilityChain: [rootCapabilityId(spaceUrl), 'urn:uuid:child'] }
    } as unknown as IZcap)
    expect(handle).toBeInstanceOf(Resource)
    expect((handle as Resource).url).toBe('https://was.example/space/s/c/r')
  })

  it('rebuilds a Space handle from the Space root capability itself', () => {
    const handle = client.fromCapability({
      '@context': 'https://w3id.org/zcap/v1',
      id: rootCapabilityId(spaceUrl),
      invocationTarget: spaceUrl,
      controller: 'did:example:alice'
    } as unknown as IZcap)
    expect(handle).toBeInstanceOf(Space)
    expect((handle as Space).url).toBe(spaceUrl)
  })

  it('throws when the chain is not rooted in a Space', () => {
    expect(() =>
      client.fromCapability({
        id: 'urn:uuid:child',
        parentCapability: 'urn:uuid:parent',
        invocationTarget: 'https://was.example/space/s/c/'
      } as unknown as IZcap)
    ).toThrow(/not rooted in a Space/)
    expect(() =>
      client.fromCapability(
        zcapFor('https://was.example/space/s/c/', 'https://was.example/')
      )
    ).toThrow(ValidationError)
  })

  it('opens a Space on another server, as the chain names it', () => {
    const elsewhere = 'https://elsewhere.example/was/space/s/'
    const handle = client.fromCapability(
      zcapFor('https://elsewhere.example/was/space/s/c/', elsewhere)
    )
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).spaceUrl).toBe(elsewhere)
    expect((handle as Collection).url).toBe(`${elsewhere}c/`)
  })

  it('refuses a target not in canonical form, which no handle request could invoke', () => {
    for (const target of [
      'https://WAS.example/space/s/c/r',
      'https://was.example:443/space/s/c/r',
      'https://was.example/space/s/c//'
    ]) {
      expect(() => client.fromCapability(zcapFor(target))).toThrow(
        ValidationError
      )
    }
  })

  it('throws a ValidationError (not a raw TypeError) on a malformed target', () => {
    expect(() => client.fromCapability(zcapFor('not a url'))).toThrow(
      ValidationError
    )
  })

  it('decodes percent-encoded id segments so they are not double-encoded', () => {
    const handle = client.fromCapability(
      zcapFor(
        'https://was.example/space/a%20b/c%2Fd',
        'https://was.example/space/a%20b/'
      )
    )
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).id).toBe('c/d')
    expect((handle as Collection).url).toBe(
      'https://was.example/space/a%20b/c%2Fd/'
    )
  })

  it('throws for a 5-segment sub-resource target instead of dropping the tail', () => {
    // A capability delegated against `{spaceUrl}c/r/meta` must not come back
    // as a Resource handle for `{spaceUrl}c/r` -- the handle would sign invocations
    // against the content URL with a capability targeting the meta URL.
    expect(() =>
      client.fromCapability(zcapFor('https://was.example/space/s/c/r/meta'))
    ).toThrow(ValidationError)
    expect(() =>
      client.fromCapability(zcapFor('https://was.example/space/s/c/r/meta'))
    ).toThrow(/sub-resource/)
  })

  it('throws for a collection-policy target instead of a reserved-id error', () => {
    expect(() =>
      client.fromCapability(zcapFor('https://was.example/space/s/c/policy'))
    ).toThrow(/sub-resource/)
  })

  it('throws for a space-policy target instead of a Collection("policy")', () => {
    expect(() =>
      client.fromCapability(zcapFor('https://was.example/space/s/policy'))
    ).toThrow(/sub-resource/)
  })
})

describe('Space.deleteWithOutcome / delete', () => {
  it('deleteWithOutcome() resolves { outcome: "deleted" } on a 2xx response', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const capability = { id: 'urn:zcap:delete-only' } as never
    const result = await client
      .spaceAt(spaceUrlFor('s'), { capability })
      .deleteWithOutcome()
    expect(result).toEqual({ outcome: 'deleted' })
    const req = lastRequest()
    expect(req?.url).toBe('https://was.example/space/s/')
    expect(req?.method).toBe('DELETE')
    expect(req?.capability).toBe(capability)
  })

  it('deleteWithOutcome() resolves { outcome: "not-found" } on a 404, without throwing', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    const result = await client.spaceAt(spaceUrlFor('s')).deleteWithOutcome()
    expect(result).toEqual({ outcome: 'not-found' })
  })

  it('deleteWithOutcome() rethrows the mapped WasError for a non-404 status', async () => {
    const { client: clientForServerError } = clientWithRequestSpy({
      fail: 500
    })
    await expect(
      clientForServerError.spaceAt(spaceUrlFor('s')).deleteWithOutcome()
    ).rejects.toThrow()

    const { client: clientForForbidden } = clientWithRequestSpy({ fail: 403 })
    await expect(
      clientForForbidden.spaceAt(spaceUrlFor('s')).deleteWithOutcome()
    ).rejects.toBeInstanceOf(AuthRequiredError)
  })

  it('delete() still resolves void on a 404 (idempotent, regression pin)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client.spaceAt(spaceUrlFor('s')).delete()
    ).resolves.toBeUndefined()
  })
})

/**
 * `spaceAt()` accepts the same `HandleOptions` as `collection()` and
 * `resource()`, so its `encryption` override is the default for every
 * Collection reached through that handle. A `'plaintext'` default is the
 * observable case: it short-circuits codec resolution, so an
 * encryption-capable client neither consults its keystore nor reads the
 * Collection Metadata object to discover a descriptor.
 */
describe('spaceAt() encryption default', () => {
  /**
   * Builds an encryption-capable `WasClient` over a stub that records every
   * request URL and a keystore that fails if it is ever consulted.
   *
   * @returns {object}
   * @returns return.client {WasClient}
   * @returns return.urls {string[]}   the recorded request URLs
   */
  function encryptingClient(): { client: WasClient; urls: string[] } {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        if ((args.method ?? 'GET') === 'GET') {
          return jsonResponse({ data: { id: 'c' } })
        }
        return jsonResponse()
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const encryption = {
      async codecFor() {
        throw new Error('the keystore must not be consulted for plaintext')
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['encryption']
    const client = new WasClient({
      baseServerUrl: baseServerUrlFor(),
      zcapClient,
      encryption,
      serviceDescription: serviceDescriptionFor()
    })
    return { client, urls }
  }

  it('honors spaceAt(url, { encryption }) as the collection() default', async () => {
    const { client, urls } = encryptingClient()
    await client
      .spaceAt(spaceUrlFor('s'), { encryption: 'plaintext' })
      .collection('c')
      .put('r', { hello: 'world' })
    expect(urls).toEqual(['https://was.example/space/s/c/r'])
  })

  it('lets collection() override the space-level default', async () => {
    const { client, urls } = encryptingClient()
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('c', { encryption: 'plaintext' })
      .put('r', { hello: 'world' })
    expect(urls).toEqual(['https://was.example/space/s/c/r'])
  })

  it('without the default, discovers the descriptor from the metadata object', async () => {
    const { client, urls } = encryptingClient()
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('c')
      .put('r', { hello: 'world' })
    expect(urls).toEqual([
      'https://was.example/space/s/c/meta',
      'https://was.example/space/s/c/r'
    ])
  })
})

/**
 * `createCollection`'s `generator.id` is typed `IDID`, which the root entry
 * exports: a caller holding a plain `string` needs the annotation to narrow
 * to it, and the handle a create returns reflects the collection's own
 * declaration rather than the Space handle's encryption default.
 */
describe('createCollection', () => {
  it('accepts a generator narrowed to the exported IDID type', async () => {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        return jsonResponse({ data: { id: 'c' } })
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      baseServerUrl: baseServerUrlFor(),
      zcapClient,
      serviceDescription: serviceDescriptionFor()
    })

    const appDid = 'did:key:zApp' as IDID
    const collection = await client
      .spaceAt(spaceUrlFor('s'))
      .createCollection({ id: 'c', generator: { id: appDid } })
    expect(collection.id).toBe('c')
    expect(urls).toEqual(['https://was.example/space/s/'])
  })

  it('does not inherit the Space handle encryption default', async () => {
    const urls: string[] = []
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      request(args: RequestArgs) {
        urls.push(args.url as string)
        return jsonResponse({ data: { id: 'c' } })
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const encryption = {
      async codecFor() {
        throw new Error('the keystore must not be consulted')
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['encryption']
    const client = new WasClient({
      baseServerUrl: baseServerUrlFor(),
      zcapClient,
      encryption,
      serviceDescription: serviceDescriptionFor()
    })

    // The Space handle defaults to `'plaintext'`, but a collection created
    // without an `encryption` declaration takes descriptor discovery, so its
    // first write reads the Collection Metadata object.
    const collection = await client
      .spaceAt(spaceUrlFor('s'), { encryption: 'plaintext' })
      .createCollection({ id: 'c' })
    await collection.put('r', { hello: 'world' })
    expect(urls).toEqual([
      'https://was.example/space/s/',
      'https://was.example/space/s/c/meta',
      'https://was.example/space/s/c/r'
    ])
  })
})

describe('createSpace', () => {
  /**
   * A stubbed client whose Create Space response carries `headers`.
   *
   * @param headers {Record<string, string>}
   * @returns {object} { client, calls }
   */
  function creatingClient(headers: Record<string, string>): {
    client: WasClient
    calls: RequestArgs[]
  } {
    const calls: RequestArgs[] = []
    const client = clientWithStub(args => {
      calls.push(args)
      return jsonResponse({ data: { id: 'new' }, status: 201, headers })
    })
    return { client, calls }
  }

  it('opens the handle on an absolute Location', async () => {
    const { client, calls } = creatingClient({ location: spaceUrlFor('new') })
    const space = await client.createSpace({ id: 'new' })
    expect(calls[0]?.url).toBe('https://was.example/spaces/')
    expect(calls[0]?.method).toBe('POST')
    expect(space.url).toBe('https://was.example/space/new/')
    expect(space.id).toBe('new')
  })

  it('opens the handle wherever the server places the Space', async () => {
    // The Location is the only source of the Space URL: nothing about it is
    // assumed from the Spaces Repository URL.
    const { client } = creatingClient({
      location: 'https://store.example/tenants/t1/vaults/v9/'
    })
    const space = await client.createSpace({ id: 'new' })
    expect(space.url).toBe('https://store.example/tenants/t1/vaults/v9/')
    expect(space.id).toBe('v9')
  })

  it('resolves a relative Location against the Spaces Repository URL', async () => {
    for (const [location, expected] of [
      ['/space/new/', 'https://was.example/space/new/'],
      ['../space/new', 'https://was.example/space/new/'],
      ['new/', 'https://was.example/spaces/new/']
    ] as const) {
      const { client } = creatingClient({ location })
      const space = await client.createSpace()
      expect(space.url).toBe(expected)
    }
  })

  it('throws WasServerError when the response carries no Location', async () => {
    // A body naming the id is not enough: the client cannot assemble the
    // Space URL from it.
    const { client } = creatingClient({})
    await expect(client.createSpace({ id: 'new' })).rejects.toThrow(
      WasServerError
    )
    await expect(client.createSpace({ id: 'new' })).rejects.toThrow(
      /carries no `Location` header/
    )
  })
})

describe('was.request', () => {
  it('signs a request to the absolute url it is given', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://was.example/space/s/c/r',
      method: 'GET'
    })
    expect(lastRequest()?.url).toBe('https://was.example/space/s/c/r')
    expect(lastRequest()?.method).toBe('GET')
  })
})

describe('was.space and was.collectionAt', () => {
  const ALICE = 'https://alice.example/'

  it('was.space(id) opens the Space the layout names, with no I/O', () => {
    const client = stubClient()
    expect(client.space('s').url).toBe(spaceUrlFor('s'))
    expect(client.space('s').url).toBe(client.spaceAt(spaceUrlFor('s')).url)
    expect(client.space('a b').url).toBe(spaceUrlFor('a b'))
  })

  it('was.space(id, options) passes the capability through', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const capability = { id: 'urn:zcap:delete-only' } as never
    await client.space('s', { capability }).deleteWithOutcome()
    expect(lastRequest()?.url).toBe(spaceUrlFor('s'))
    expect(lastRequest()?.capability).toBe(capability)
  })

  it('collectionAt opens a Collection under a base-layout Space', () => {
    const client = stubClient()
    const url = `${spaceUrlFor('s')}posts/`
    const collection = client.collectionAt(url)
    expect(collection).toBeInstanceOf(Collection)
    expect(collection.id).toBe('posts')
    expect(collection.spaceUrl).toBe(spaceUrlFor('s'))
    expect(collection.url).toBe(
      client.spaceAt(spaceUrlFor('s')).collection('posts').url
    )
  })

  it('collectionAt opens a Collection at an origin-root Space', () => {
    const client = stubClient()
    const collection = client.collectionAt('https://alice.example/posts/')
    expect(collection.spaceUrl).toBe(ALICE)
    expect(collection.id).toBe('posts')
    const viaSpace = client.spaceAt(ALICE).collection('posts')
    expect(collection.url).toBe(viaSpace.url)
    expect(collection.spaceUrl).toBe(viaSpace.spaceUrl)
  })

  it('collectionAt refuses a reserved last segment and a URL with no segment', () => {
    const client = stubClient()
    expect(() => client.collectionAt(`${spaceUrlFor('s')}policy/`)).toThrow(
      ValidationError
    )
    expect(() => client.collectionAt(ALICE)).toThrow(ValidationError)
    expect(() => client.collectionAt(`${ALICE}service/`)).toThrow(
      ValidationError
    )
  })

  it('collectionAt refuses a URL whose last segment is not in canonical form', () => {
    const client = stubClient()
    // The handle re-encodes the decoded id, so `%21` would come back as `!`
    // and lower-case hex as upper-case: a different URL from the one given.
    for (const url of [
      `${spaceUrlFor('s')}%21/`,
      `${spaceUrlFor('s')}a%2fb/`
    ]) {
      expect(() => client.collectionAt(url)).toThrow(/canonical form/)
    }
    expect(client.collectionAt(`${spaceUrlFor('s')}a%2Fb/`).id).toBe('a/b')
  })
})

describe('a client fixed on a Space (forSpace)', () => {
  const ALICE = 'https://alice.example/'

  /**
   * A `forSpace` client whose stub `ZcapClient` echoes `delegate(...)` args
   * back as the delegated zcap, parented on the capability it was given.
   *
   * @returns {WasClient}
   */
  function fixedClient(): WasClient {
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async delegate(args: Record<string, unknown>) {
        return {
          ...args,
          id: 'urn:uuid:delegated',
          parentCapability: args.capability,
          allowedAction: args.allowedActions
        }
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    return WasClient.forSpace({ spaceUrl: ALICE, zcapClient })
  }

  it('opens the origin-root Space, which has no id', () => {
    const client = fixedClient()
    const space = client.spaceAt(ALICE)
    expect(space.url).toBe(ALICE)
    expect(space.id).toBeUndefined()
    expect(space.collection('posts').url).toBe('https://alice.example/posts/')
    expect(client.spaceAt(client.spaceUrl!).url).toBe(ALICE)
  })

  it('roots capabilities at the origin for the Space and a Collection', () => {
    expect(rootCapabilityId(ALICE)).toBe(
      `urn:zcap:root:${encodeURIComponent(ALICE)}`
    )
    const posts = fixedClient().spaceAt(ALICE).collection('posts')
    expect(rootCapabilityId(posts.url)).toBe(
      `urn:zcap:root:${encodeURIComponent('https://alice.example/posts/')}`
    )
  })

  it('round-trips a grant through fromCapability at the origin', async () => {
    const client = fixedClient()
    const zcap = await client
      .spaceAt(ALICE)
      .collection('posts')
      .grant({ to: 'did:example:bob', actions: ['GET'] })
    expect(zcap.parentCapability).toBe(rootCapabilityId(ALICE))
    expect(zcap.invocationTarget).toBe('https://alice.example/posts/')
    const handle = client.fromCapability(zcap)
    expect(handle).toBeInstanceOf(Collection)
    expect((handle as Collection).url).toBe('https://alice.example/posts/')
    expect((handle as Collection).spaceUrl).toBe(ALICE)
    expect((handle as Collection).id).toBe('posts')
  })

  it('throws NotSupportedError from the id-addressed operations', async () => {
    const client = fixedClient()
    expect(() => client.space('s')).toThrow(NotSupportedError)
    await expect(client.createSpace()).rejects.toThrow(NotSupportedError)
    await expect(client.listSpaces()).rejects.toThrow(NotSupportedError)
  })
})
