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

import { ValidationError, WasClient, allowsAction } from '../../src/index.js'
import { rootCapabilityId } from '../../src/paths.js'
import {
  clientWithRequestSpy,
  serviceDescriptionFor,
  serviceUrlFor,
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
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `delegate(...)` call and echoes its args back as the delegated zcap.
 *
 * @returns {object}
 * @returns return.client {WasClient}
 * @returns return.lastDelegate {function} returns the captured delegate args
 */
function clientWithDelegateSpy(): {
  client: WasClient
  lastDelegate: () => DelegateArgs | undefined
} {
  let captured: DelegateArgs | undefined
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async delegate(args: DelegateArgs) {
      captured = args
      return { ...args, allowedAction: args.allowedActions }
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({
    serviceUrl: serviceUrlFor(),
    zcapClient,
    serviceDescription: serviceDescriptionFor()
  })
  return { client, lastDelegate: () => captured }
}

describe('was.grant (delegation)', () => {
  it('normalizes lowercase actions to uppercase before signing', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['get'],
      target: 'https://was.example/space/s/c/r'
    })
    expect(lastDelegate()?.allowedActions).toEqual(['GET'])
  })

  it('grants HEAD, the action a HEAD request is verified under', async () => {
    // Typed, not cast: `ActionInput` names HEAD, so a read grant that covers
    // a metadata probe needs no escape hatch. The server checks a HEAD
    // request against the `HEAD` action, not `GET`.
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET', 'head'],
      target: 'https://was.example/space/s/c/'
    })
    expect(lastDelegate()?.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('passes through controller, invocationTarget, expires and capability', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const expires = '2026-01-01T00:00:00Z'
    const parent = { id: 'urn:zcap:parent' }
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET', 'put'],
      target: 'https://was.example/space/s',
      expires,
      capability: parent as never
    })
    const args = lastDelegate()
    expect(args?.controller).toBe('did:example:bob')
    expect(args?.invocationTarget).toBe('https://was.example/space/s')
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
    expect(args?.invocationTarget).toBe('https://was.example/space/s/c/')
  })

  it('roots a space grant at itself', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client
      .spaceAt(spaceUrlFor('s'))
      .grant({ to: 'did:example:bob', actions: ['GET'] })

    const args = lastDelegate()
    expect(args?.capability).toBe(spaceRoot)
    expect(args?.invocationTarget).toBe('https://was.example/space/s/')
  })

  it('roots a handle grant at its space when the target is narrowed', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.spaceAt(spaceUrlFor('s')).grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/space/s/c/r'
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://was.example/space/s/c/r'
    )
  })

  it('accepts the Space in its bare form as a target, delegating the canonical form', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.spaceAt(spaceUrlFor('s')).grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/space/s'
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://was.example/space/s/'
    )
  })

  it('refuses a sibling of the Space that shares its prefix', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await expect(
      client.spaceAt(spaceUrlFor('s')).grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://was.example/space/s-evil/'
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
          target: 'https://was.example/space/other/c/'
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

  it('roots a was.grant with no spaceUrl at the target itself', async () => {
    // With no `spaceUrl` and no parent, the client does not guess a Space
    // from the target's shape: ezcap's default root names the target, which
    // is the same `urn:zcap:root:` id spelled out here.
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const target of [
      'https://was.example/space/s/c/r',
      'https://was.example/kms/keystores/k1',
      'https://elsewhere.example/space/s/c'
    ]) {
      await client.grant({ to: 'did:example:bob', actions: ['GET'], target })
      const args = lastDelegate()
      expect(args?.capability).toBeUndefined()
      expect(args?.invocationTarget).toBe(target)
    }
  })

  it('roots a was.grant with spaceUrl at that Space', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/space/s/c/r',
      spaceUrl: spaceUrlFor('s')
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://was.example/space/s/c/r'
    )
  })

  it('canonicalizes spaceUrl before minting the root id', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const spaceUrl of [
      'https://was.example/space/s',
      'https://WAS.example:443/space/s//'
    ]) {
      await client.grant({
        to: 'did:example:bob',
        actions: ['GET'],
        target: 'https://was.example/space/s/c/',
        spaceUrl
      })
      expect(lastDelegate()?.capability).toBe(spaceRoot)
    }
  })

  it('throws ValidationError when target is outside spaceUrl', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    for (const target of [
      'https://was.example/space/other/c/r',
      'https://was.example/space/s2/c/',
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
        target: 'https://was.example/space/s/c/',
        spaceUrl: 'https://was.example/'
      })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('keeps a path prefix the Space URL carries in the root id', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const spaceUrl = 'https://host.example/was/space/s/'

    await client
      .spaceAt(spaceUrl)
      .collection('c')
      .grant({
        to: 'did:example:bob',
        actions: ['GET']
      })

    expect(lastDelegate()?.capability).toBe(
      `urn:zcap:root:${encodeURIComponent('https://host.example/was/space/s/')}`
    )
    expect(lastDelegate()?.invocationTarget).toBe(
      'https://host.example/was/space/s/c/'
    )
  })
})

/**
 * Two hygiene properties of the entry point itself: a grant that names nothing
 * to delegate is refused as a `ValidationError` (ezcap would answer a raw
 * `TypeError`, which a consumer catching `WasError` never sees), and
 * delegating never touches the invocation signer -- so a client built for
 * delegation alone can still hand out capabilities.
 */
describe('allowsAction', () => {
  const zcap = (allowedAction?: string | string[]) =>
    ({
      invocationTarget: 'https://was.example/space/s/c/',
      allowedAction
    }) as never

  it('matches a listed action case-insensitively', () => {
    expect(allowsAction({ zcap: zcap(['get', 'HEAD']), action: 'GET' })).toBe(
      true
    )
    expect(allowsAction({ zcap: zcap('post'), action: 'POST' })).toBe(true)
    expect(allowsAction({ zcap: zcap(['GET', 'HEAD']), action: 'POST' })).toBe(
      false
    )
  })

  it('reads an absent or empty allowedAction, or no zcap, as unrestricted', () => {
    expect(allowsAction({ zcap: zcap(), action: 'DELETE' })).toBe(true)
    expect(allowsAction({ zcap: zcap([]), action: 'DELETE' })).toBe(true)
    expect(allowsAction({ action: 'DELETE' })).toBe(true)
  })
})

describe('was.grant input validation', () => {
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
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serviceUrl: serviceUrlFor(),
      serviceDescription: serviceDescriptionFor(),
      zcapClient
    })

    expect(() => client.spaceAt(spaceUrlFor('s'))).not.toThrow()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/space/s/c/r'
    })
    expect(captured?.controller).toBe('did:example:bob')

    await client
      .spaceAt(spaceUrlFor('s'))
      .grant({ to: 'did:example:bob', actions: ['GET'] })
    expect(captured?.invocationTarget).toBe('https://was.example/space/s/')
  })
})

describe('was.request action normalization', () => {
  it('signs a lowercase method under the uppercase action grant() delegates', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://was.example/space/s/c/r',
      method: 'put'
    })
    expect(lastRequest()?.method).toBe('PUT')
    expect(lastRequest()?.action).toBe('PUT')
  })

  it('uppercases an explicit lowercase action', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.request({
      url: 'https://was.example/space/s/c/r',
      method: 'GET',
      action: 'head'
    })
    expect(lastRequest()?.method).toBe('GET')
    expect(lastRequest()?.action).toBe('HEAD')
  })
})
