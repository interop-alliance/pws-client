/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the delegation primitive. `delegateGrant` maps `GrantOptions`
 * onto `zcapClient.delegate(...)`, normalizing action verbs to uppercase so a
 * lowercase grant (`'get'`) still validates on the server (which matches
 * actions case-sensitively against `'GET'`). A stub `ZcapClient` captures the
 * delegate args, so no signer or server is involved.
 */
import { describe, it, expect } from 'vitest'

import {
  AUTHZ_PROFILE_SPEC_ID,
  NotSupportedError,
  TargetDereferenceError,
  ValidationError,
  PwsClient,
  allowsAction
} from '../../src/index.js'
import { rootCapabilityId } from '../../src/paths/index.js'
import {
  clientWithRequestSpy,
  serviceDescriptionFor,
  baseServerUrlFor,
  spaceUrlFor
} from '../helpers/stubClient.js'

interface DelegateArgs {
  controller?: string
  invocationTarget?: string
  allowedActions?: string[]
  expires?: string | Date
  capability?: unknown
}

/**
 * Builds a `PwsClient` over a stub `ZcapClient` that records the most recent
 * `delegate(...)` call and echoes its args back as the delegated zcap.
 *
 * @returns {object}
 * @returns return.client {PwsClient}
 * @returns return.lastDelegate {function} returns the captured delegate args
 */
function clientWithDelegateSpy(): {
  client: PwsClient
  lastDelegate: () => DelegateArgs | undefined
} {
  let captured: DelegateArgs | undefined
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async delegate(args: DelegateArgs) {
      captured = args
      return { ...args, allowedAction: args.allowedActions }
    }
  } as unknown as ConstructorParameters<typeof PwsClient>[0]['zcapClient']
  const client = new PwsClient({
    baseServerUrl: baseServerUrlFor(),
    zcapClient,
    serviceDescription: serviceDescriptionFor()
  })
  return { client, lastDelegate: () => captured }
}

describe('pws.grant (delegation)', () => {
  it('normalizes lowercase actions to uppercase before signing', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['get'],
      target: 'https://pws.example/space/s/c/r'
    })
    expect(lastDelegate()?.allowedActions).toEqual(['GET'])
  })

  it('passes through controller, invocationTarget, expires and capability', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const expires = '2026-01-01T00:00:00Z'
    const parent = { id: 'urn:zcap:parent' }
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET', 'put'],
      target: 'https://pws.example/space/s',
      expires,
      capability: parent as never
    })
    const args = lastDelegate()
    expect(args?.controller).toBe('did:example:bob')
    expect(args?.invocationTarget).toBe('https://pws.example/space/s')
    expect(args?.allowedActions).toEqual(['GET', 'PUT'])
    expect(args?.expires).toBe(expires)
    expect(args?.capability).toBe(parent)
  })
})

/**
 * A grant handed a parent `capability` attenuates it. Without one, `spaceUrl`
 * decides the root: given, the grant roots at the Space's root capability and
 * carries the narrower target as an attenuated `invocationTarget`; absent, it
 * roots at the target's own root capability (ezcap's default). Both grant the
 * same access, but only a Space-rooted chain can be revoked (revocation is
 * Space-scoped and the endpoint requires the chain to root exactly in the
 * Space). The `space` / `collection` grant sugar fills `spaceUrl` from the
 * handle, so a grant made through a handle is always revocable.
 */
describe('grant rooting (revocability)', () => {
  const spaceRoot = rootCapabilityId(spaceUrlFor('s'))

  it('roots a collection grant at its space, attenuating the target', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('c')
      .grant({
        to: 'did:example:bob',
        actions: ['GET']
      })

    const args = lastDelegate()
    expect(args?.capability).toBe(spaceRoot)
    expect(args?.invocationTarget).toBe('https://pws.example/space/s/c/')
  })

  it('roots a space grant at itself', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client
      .spaceAt(spaceUrlFor('s'))
      .grant({ to: 'did:example:bob', actions: ['GET'] })

    const args = lastDelegate()
    expect(args?.capability).toBe(spaceRoot)
    expect(args?.invocationTarget).toBe('https://pws.example/space/s/')
  })

  it('roots a handle grant at its space when the target is narrowed', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.spaceAt(spaceUrlFor('s')).grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://pws.example/space/s/c/r'
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://pws.example/space/s/c/r'
    )
  })

  it('accepts the Space in its bare form as a target, delegating the canonical form', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.spaceAt(spaceUrlFor('s')).grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://pws.example/space/s'
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://pws.example/space/s/'
    )
  })

  it('refuses a query-form target on the bare Space, which the server would refuse', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client.spaceAt(spaceUrlFor('s')).grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://pws.example/space/s?x=1'
      })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a dot-segment target that escapes the Space once normalized', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client.spaceAt(spaceUrlFor('s')).grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://pws.example/space/s/../other/'
      })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a sibling of the Space that shares its prefix', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client.spaceAt(spaceUrlFor('s')).grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://pws.example/space/s-evil/'
      })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a handle grant whose target is outside its space', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client
        .spaceAt(spaceUrlFor('s'))
        .collection('c')
        .grant({
          to: 'did:example:bob',
          actions: ['GET'],
          target: 'https://pws.example/space/other/c/'
        })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('re-delegation keeps the bound capability as the parent', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const held = { id: 'urn:uuid:held' }
    await client
      .spaceAt(spaceUrlFor('s'), { capability: held as never })
      .collection('c')
      .grant({ to: 'did:example:bob', actions: ['GET'] })

    expect(lastDelegate()?.capability).toBe(held)
  })

  it('re-delegates from a Resource handle bound to a capability', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const held = { id: 'urn:uuid:held' }
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('c')
      .resource('r', { capability: held as never })
      .grant({ to: 'did:example:bob', actions: ['GET'] })

    expect(lastDelegate()?.capability).toBe(held)
    expect(lastDelegate()?.invocationTarget).toBe(`${spaceUrlFor('s')}c/r`)
  })

  it('roots a pws.grant with no spaceUrl at the target itself', async () => {
    // With no `spaceUrl` and no parent, the client does not guess a Space
    // from the target's shape: ezcap's default root names the target, which
    // is the same `urn:zcap:root:` id spelled out here.
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const target of [
      'https://pws.example/space/s/c/r',
      'https://pws.example/kms/keystores/k1',
      'https://elsewhere.example/space/s/c'
    ]) {
      await client.grant({ to: 'did:example:bob', actions: ['GET'], target })
      const args = lastDelegate()
      expect(args?.capability).toBeUndefined()
      expect(args?.invocationTarget).toBe(target)
    }
  })

  it('roots a pws.grant with spaceUrl at that Space', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://pws.example/space/s/c/r',
      spaceUrl: spaceUrlFor('s')
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://pws.example/space/s/c/r'
    )
  })

  it('canonicalizes spaceUrl before minting the root id', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const spaceUrl of [
      'https://pws.example/space/s',
      'https://PWS.example:443/space/s//'
    ]) {
      await client.grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://pws.example/space/s/c/',
        spaceUrl
      })
      expect(lastDelegate()?.capability).toBe(spaceRoot)
    }
  })

  it('throws ValidationError when target is outside spaceUrl', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const target of [
      'https://pws.example/space/other/c/r',
      'https://pws.example/space/s2/c/',
      'https://elsewhere.example/space/s/c/'
    ]) {
      await expect(
        client.grant({
          to: 'did:example:bob',
          actions: ['GET'],
          target,
          spaceUrl: spaceUrlFor('s')
        })
      ).rejects.toBeInstanceOf(ValidationError)
    }
    expect(lastDelegate()).toBeUndefined()
  })

  it('throws ValidationError when spaceUrl is not a Space URL', async () => {
    const { client } = clientWithDelegateSpy()
    await expect(
      client.grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://pws.example/space/s/c/',
        spaceUrl: 'https://pws.example/space/s/?q=1'
      })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('keeps a path prefix the Space URL carries in the root id', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const spaceUrl = 'https://host.example/pws/space/s/'

    await client
      .spaceAt(spaceUrl)
      .collection('c')
      .grant({
        to: 'did:example:bob',
        actions: ['GET']
      })

    expect(lastDelegate()?.capability).toBe(
      `urn:zcap:root:${encodeURIComponent('https://host.example/pws/space/s/')}`
    )
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://host.example/pws/space/s/c/'
    )
  })
})

/**
 * Two hygiene properties of the entry point itself: a grant that names nothing
 * to delegate is refused as a `ValidationError` (ezcap would answer a raw
 * `TypeError`, which a consumer catching `PwsError` never sees), and
 * delegating never touches the invocation signer -- so a client built for
 * delegation alone can still hand out capabilities.
 */
describe('allowsAction', () => {
  const zcap = (allowedAction?: string | string[]) =>
    ({
      invocationTarget: 'https://pws.example/space/s/c/',
      allowedAction
    }) as never

  it('matches a listed action case-insensitively', () => {
    expect(allowsAction({ zcap: zcap(['get', 'PUT']), action: 'GET' })).toBe(
      true
    )
    expect(allowsAction({ zcap: zcap('post'), action: 'POST' })).toBe(true)
    expect(allowsAction({ zcap: zcap(['GET']), action: 'POST' })).toBe(false)
  })

  it('reads an absent or empty allowedAction, or no zcap, as unrestricted', () => {
    expect(allowsAction({ zcap: zcap(), action: 'DELETE' })).toBe(true)
    expect(allowsAction({ zcap: zcap([]), action: 'DELETE' })).toBe(true)
    expect(allowsAction({ action: 'DELETE' })).toBe(true)
  })
})

describe('pws.grant input validation', () => {
  it('throws ValidationError when neither target nor capability is given', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client.grant({ to: 'did:example:bob', actions: ['GET'] })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('a delegation-only client can grant and build handles', async () => {
    let captured: DelegateArgs | undefined
    const zcapClient = {
      // No `invocationSigner`: this client delegates but never invokes.
      delegationSigner: { id: 'did:example:alice#key-1' },
      async delegate(args: DelegateArgs) {
        captured = args
        return args
      }
    } as unknown as ConstructorParameters<typeof PwsClient>[0]['zcapClient']
    const client = new PwsClient({
      baseServerUrl: baseServerUrlFor(),
      serviceDescription: serviceDescriptionFor(),
      zcapClient
    })

    expect(() => client.spaceAt(spaceUrlFor('s'))).not.toThrow()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://pws.example/space/s/c/r'
    })
    expect(captured?.controller).toBe('did:example:bob')

    await client
      .spaceAt(spaceUrlFor('s'))
      .grant({ to: 'did:example:bob', actions: ['GET'] })
    expect(captured?.invocationTarget).toBe('https://pws.example/space/s/')
  })
})

describe('pws.request action normalization', () => {
  it('signs a lowercase method under the uppercase action grant() delegates', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://pws.example/space/s/c/r',
      method: 'put'
    })
    expect(lastRequest()?.method).toBe('PUT')
    expect(lastRequest()?.action).toBe('PUT')
  })

  it('uppercases an explicit lowercase action', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://pws.example/space/s/c/r',
      method: 'POST',
      action: 'get'
    })
    expect(lastRequest()?.method).toBe('POST')
    expect(lastRequest()?.action).toBe('GET')
  })

  it('signs a HEAD request with the GET action', async () => {
    // HEAD is not an action of its own: a HEAD request is authorized as a
    // GET, so a GET grant covers it.
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://pws.example/space/s/c/r',
      method: 'head'
    })
    expect(lastRequest()?.method).toBe('HEAD')
    expect(lastRequest()?.action).toBe('GET')
  })

  it('signs a HEAD request under a GET grant with the GET action', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const capability = {
      id: 'urn:zcap:delegated:abc',
      invocationTarget: 'https://pws.example/space/s/c/',
      allowedAction: ['GET']
    } as never
    await client.request({
      url: 'https://pws.example/space/s/c/r',
      method: 'HEAD',
      capability
    })
    expect(lastRequest()?.method).toBe('HEAD')
    expect(lastRequest()?.action).toBe('GET')
    expect(lastRequest()?.capability).toBe(capability)
  })

  it('signs an explicit action as given, on a HEAD request too', async () => {
    // The escape hatch does not rewrite a caller's action, so a conformance
    // test can still send the `HEAD` action a server refuses.
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://pws.example/space/s/c/r',
      method: 'HEAD',
      action: 'HEAD'
    })
    expect(lastRequest()?.action).toBe('HEAD')
  })
})

describe('grants from a Space handle with `didUrl`', () => {
  const SPACE = spaceUrlFor('s')
  const DID_URL = 'did:webvh:QmScid:alice.example/'

  /**
   * A client over a delegate spy whose server advertises `did-url-targets`
   * (unless `advertised` is false) and whose `dereferenceTarget` hook maps
   * `DID_URL` to the Space, with `aliases` mapped first.
   *
   * @param [options] {object}
   * @param [options.advertised] {boolean}
   * @param [options.aliases] {Record<string, string>}   DID URL to https URL
   * @returns {object} { client, lastDelegate, dereferenced }
   */
  function didUrlClient({
    advertised = true,
    aliases = {}
  }: { advertised?: boolean; aliases?: Record<string, string> } = {}): {
    client: PwsClient
    lastDelegate: () => DelegateArgs | undefined
    dereferenced: string[]
  } {
    let captured: DelegateArgs | undefined
    const dereferenced: string[] = []
    const description = serviceDescriptionFor()
    if (advertised) {
      for (const entry of description.specs[AUTHZ_PROFILE_SPEC_ID] ?? []) {
        entry.features = ['did-url-targets']
      }
    }
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async delegate(args: DelegateArgs) {
        captured = args
        return { ...args, allowedAction: args.allowedActions }
      }
    } as unknown as ConstructorParameters<typeof PwsClient>[0]['zcapClient']
    const client = new PwsClient({
      baseServerUrl: baseServerUrlFor(),
      zcapClient,
      serviceDescription: description,
      dereferenceTarget: async ({ invocationTarget }) => {
        dereferenced.push(invocationTarget)
        if (Object.hasOwn(aliases, invocationTarget)) {
          return aliases[invocationTarget] as string
        }
        if (!invocationTarget.startsWith(DID_URL)) {
          throw new Error(`No mapping for ${invocationTarget}.`)
        }
        return `${SPACE}${invocationTarget.slice(DID_URL.length)}`
      }
    })
    return { client, lastDelegate: () => captured, dereferenced }
  }

  const grantOptions = { to: 'did:example:bob', actions: ['GET' as const] }

  it('refuses a `didUrl` that is not a root DID URL, at the handle', () => {
    const { client, dereferenced } = didUrlClient()
    for (const didUrl of [
      'did:webvh:QmScid:alice.example',
      'did:webvh:QmScid:alice.example/?versionId=1',
      'did:webvh:QmScid:alice.example/#key',
      'https://alice.example/'
    ]) {
      expect(() => client.space('s', { didUrl })).toThrow(ValidationError)
      expect(() => client.spaceAt(SPACE, { didUrl })).toThrow(ValidationError)
    }
    expect(dereferenced).toEqual([])
  })

  it('roots a Space grant in the DID URL root', async () => {
    const { client, lastDelegate } = didUrlClient()
    await client.space('s', { didUrl: DID_URL }).grant(grantOptions)
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(DID_URL))
    expect(lastDelegate()?.capability).toBe(
      `urn:zcap:root:${encodeURIComponent(DID_URL)}`
    )
    expect(lastDelegate()?.invocationTarget).toBe(DID_URL)
  })

  it('names the handle path within the Space on Collection and Resource grants', async () => {
    const { client, lastDelegate } = didUrlClient()
    const photos = client.space('s', { didUrl: DID_URL }).collection('photos')
    await photos.grant(grantOptions)
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(DID_URL))
    expect(lastDelegate()?.invocationTarget).toBe(`${DID_URL}photos/`)

    await photos.resource('cat 1').grant(grantOptions)
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(DID_URL))
    expect(lastDelegate()?.invocationTarget).toBe(`${DID_URL}photos/cat%201`)
  })

  it('translates an explicit https target, and takes a DID URL one as given', async () => {
    const { client, lastDelegate } = didUrlClient({
      aliases: { [`${DID_URL}pics/`]: `${SPACE}photos/` }
    })
    const space = client.space('s', { didUrl: DID_URL })
    await space.grant({ ...grantOptions, target: `${SPACE}photos/doc-1` })
    expect(lastDelegate()?.invocationTarget).toBe(`${DID_URL}photos/doc-1`)

    await space.grant({ ...grantOptions, target: `${DID_URL}pics/` })
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(DID_URL))
    expect(lastDelegate()?.invocationTarget).toBe(`${DID_URL}pics/`)
  })

  it('refuses a target outside the Space, or with a query', async () => {
    const { client, lastDelegate } = didUrlClient({
      aliases: {
        [`${DID_URL}elsewhere/`]: spaceUrlFor('other'),
        [`${DID_URL}dots/`]: `${SPACE}../other/`
      }
    })
    const space = client.space('s', { didUrl: DID_URL })
    for (const target of [
      spaceUrlFor('other'),
      'did:webvh:QmOther:alice.example/photos/',
      `${DID_URL}elsewhere/`,
      `${DID_URL}dots/`,
      `${SPACE}photos/?versionId=1`,
      `${DID_URL}photos/?versionId=1`
    ]) {
      await expect(
        space.grant({ ...grantOptions, target })
      ).rejects.toBeInstanceOf(ValidationError)
    }
    await expect(
      space.grant({ ...grantOptions, spaceUrl: spaceUrlFor('other') })
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a server without `did-url-targets`, before any dereference', async () => {
    const { client, lastDelegate, dereferenced } = didUrlClient({
      advertised: false
    })
    const photos = client.space('s', { didUrl: DID_URL }).collection('photos')
    const refusal = photos.grant(grantOptions)
    await expect(refusal).rejects.toBeInstanceOf(NotSupportedError)
    await expect(refusal).rejects.toThrow(/did-url-targets/)
    expect(dereferenced).toEqual([])
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a `didUrl` that does not dereference to the Space', async () => {
    const { client, lastDelegate } = didUrlClient({
      aliases: { [DID_URL]: spaceUrlFor('other') }
    })
    await expect(
      client.space('s', { didUrl: DID_URL }).grant(grantOptions)
    ).rejects.toThrow(/dereferences to/)
    expect(lastDelegate()).toBeUndefined()
  })

  it('refuses a link a longer `PathHandler` maps elsewhere', async () => {
    const { client, lastDelegate } = didUrlClient({
      aliases: { [`${DID_URL}photos/`]: `${SPACE}private/` }
    })
    await expect(
      client
        .space('s', { didUrl: DID_URL })
        .collection('photos')
        .grant(grantOptions)
    ).rejects.toBeInstanceOf(ValidationError)
    expect(lastDelegate()).toBeUndefined()
  })

  it('reports a `didUrl` that cannot be dereferenced', async () => {
    const { client } = didUrlClient()
    await expect(
      client
        .space('s', { didUrl: 'did:webvh:QmUnknown:alice.example/' })
        .grant(grantOptions)
    ).rejects.toBeInstanceOf(TargetDereferenceError)
  })

  it('does not apply `didUrl` under a parent capability', async () => {
    const { client, lastDelegate, dereferenced } = didUrlClient()
    const parent = { id: 'urn:uuid:parent' } as never
    const space = client.space('s', { didUrl: DID_URL })
    await space.grant({ ...grantOptions, capability: parent })
    expect(lastDelegate()?.capability).toBe(parent)
    expect(lastDelegate()?.invocationTarget).toBe(SPACE)
    expect(dereferenced).toEqual([])
  })

  it('issues https grants from a handle without `didUrl`', async () => {
    const { client, lastDelegate, dereferenced } = didUrlClient()
    await client.space('s').collection('photos').grant(grantOptions)
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(SPACE))
    expect(lastDelegate()?.invocationTarget).toBe(`${SPACE}photos/`)

    await client
      .space('s')
      .collection('photos')
      .resource('r')
      .grant(grantOptions)
    expect(lastDelegate()?.capability).toBe(rootCapabilityId(SPACE))
    expect(lastDelegate()?.invocationTarget).toBe(`${SPACE}photos/r`)
    expect(dereferenced).toEqual([])
  })
})
