/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the revocation primitive. `submitRevocation` POSTs a delegated
 * capability to `{spaceUrl}zcaps/revocations/:capabilityId`, invoking that
 * URL's own root capability. `was.revoke` reads the Space off the
 * capability's delegation chain, whose root capability id encodes the Space
 * URL. A stub `ZcapClient` captures the request args, so
 * no signer or server is involved; the live behavior is covered by
 * `test/integration/revocation.test.ts`.
 */
import { describe, it, expect } from 'vitest'

import { ValidationError, NotFoundError } from '../../src/index.js'
import type { IDelegatedZcap } from '../../src/index.js'
import { rootCapabilityId } from '../../src/paths/index.js'
import { clientWithRequestSpy, spaceUrlFor } from '../helpers/stubClient.js'

const SPACE_URL = spaceUrlFor('space-1')
const CAPABILITY_ID = 'urn:uuid:6f1c1b0e-1f3a-4a5e-9a1e-3b2c4d5e6f70'

/**
 * A delegated capability granting read/write on a collection in the Space at
 * `spaceUrl`, shaped like the output of `space.grant()` (proof elided to what
 * the client actually reads). `chain: 'parent'` names the root only as the
 * string `parentCapability` of a single-level delegation; `chain: 'proof'`
 * makes it a two-level delegation whose parent is another delegated
 * capability, so only `proof.capabilityChain` names the root.
 *
 * @param [options] {object}
 * @param [options.invocationTarget] {string}   the capability's target URL
 * @param [options.rootId] {string}   the chain's root capability id
 * @param [options.chain] {'proof' | 'parent'}   where the root is named
 * @returns {IDelegatedZcap}
 */
function delegatedZcap({
  invocationTarget = `${SPACE_URL}notes/`,
  rootId = rootCapabilityId(SPACE_URL),
  chain = 'proof'
}: {
  invocationTarget?: string
  rootId?: string
  chain?: 'proof' | 'parent'
} = {}): IDelegatedZcap {
  const parentId = 'urn:uuid:0b6c5b3e-parent'
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id: CAPABILITY_ID,
    parentCapability: chain === 'proof' ? parentId : rootId,
    controller: 'did:example:bob',
    invocationTarget,
    allowedAction: ['GET', 'PUT'],
    expires: '2030-01-01T00:00:00Z',
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00Z',
      verificationMethod: 'did:example:alice#key-1',
      proofPurpose: 'capabilityDelegation',
      capabilityChain: chain === 'proof' ? [rootId, parentId] : [],
      proofValue: 'zStubProofValue'
    }
  }
}

describe('space.revoke (revocation)', () => {
  it('POSTs to the space revocation endpoint, framing the capability id', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.spaceAt(SPACE_URL).revoke(delegatedZcap())

    const args = lastRequest()
    expect(args?.method).toBe('POST')
    expect(args?.url).toBe(
      `${SPACE_URL}zcaps/revocations/${encodeURIComponent(CAPABILITY_ID)}`
    )
    // The `urn:uuid:` colons must be percent-encoded into the single final
    // segment, not left to split it.
    expect(args?.url).toContain('urn%3Auuid%3A')
  })

  it('sends the capability verbatim as the body', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const zcap = delegatedZcap()
    await client.spaceAt(SPACE_URL).revoke(zcap)

    expect(lastRequest()?.json).toBe(zcap)
  })

  it('leaves `action` unset so it defaults to the POST method', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.spaceAt(SPACE_URL).revoke(delegatedZcap())

    // The WAS route expects the HTTP verb, never ezcap's `read`/`write`.
    expect(lastRequest()?.action).toBe('POST')
  })

  it('invokes the revocation URL root capability, in object form', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.spaceAt(SPACE_URL).revoke(delegatedZcap())

    const { capability, url } = lastRequest() ?? {}
    // Object form, not a `urn:zcap:root:` string: ezcap rejects string root ids
    // whose target is not `https:`.
    expect(typeof capability).toBe('object')
    expect(capability?.['@context']).toBe('https://w3id.org/zcap/v1')
    expect(capability?.invocationTarget).toBe(url)
    expect(capability?.id).toBe(`urn:zcap:root:${encodeURIComponent(url!)}`)
    // Client-side only -- the server re-derives the real controller.
    expect(capability?.controller).toBe('did:example:alice')
  })

  it('refuses to revoke a root capability, before any request', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const root = {
      '@context': 'https://w3id.org/zcap/v1',
      id: rootCapabilityId(SPACE_URL),
      invocationTarget: SPACE_URL,
      controller: 'did:example:alice'
    } as unknown as IDelegatedZcap

    await expect(client.spaceAt(SPACE_URL).revoke(root)).rejects.toThrow(
      ValidationError
    )
    expect(lastRequest()).toBeUndefined()
  })

  describe('error mapping', () => {
    it('maps the resubmission 400 to ValidationError (not idempotent)', async () => {
      const { client } = clientWithRequestSpy({ fail: 400 })
      const error = await client
        .spaceAt(SPACE_URL)
        .revoke(delegatedZcap())
        .catch((err: unknown) => err)

      expect(error).toBeInstanceOf(ValidationError)
      expect((error as ValidationError).status).toBe(400)
    })

    it('maps the non-participant 404 to NotFoundError', async () => {
      const { client } = clientWithRequestSpy({ fail: 404 })

      await expect(
        client.spaceAt(SPACE_URL).revoke(delegatedZcap())
      ).rejects.toThrow(NotFoundError)
    })
  })
})

describe('was.revoke (space derived from the delegation chain)', () => {
  const revocationUrl = `${SPACE_URL}zcaps/revocations/${encodeURIComponent(CAPABILITY_ID)}`

  it('reads the space off the first entry of proof.capabilityChain', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(delegatedZcap({ chain: 'proof' }))

    expect(lastRequest()?.url).toBe(revocationUrl)
  })

  it('reads the space off a string parentCapability', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(delegatedZcap({ chain: 'parent' }))

    expect(lastRequest()?.url).toBe(revocationUrl)
  })

  it('reads the space off the chain whatever depth the target addresses', async () => {
    const { client, calls } = clientWithRequestSpy()
    for (const invocationTarget of [
      SPACE_URL,
      `${SPACE_URL}notes/`,
      `${SPACE_URL}notes/doc-1`,
      `${SPACE_URL}notes/doc-1/meta`
    ]) {
      await client.revoke(delegatedZcap({ invocationTarget }))
    }

    expect(calls.map(call => call.url)).toEqual(Array(4).fill(revocationUrl))
  })

  it('canonicalizes the Space URL the root id names', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(
      delegatedZcap({
        rootId: rootCapabilityId('https://WAS.example:443/space/space-1')
      })
    )

    expect(lastRequest()?.url).toBe(revocationUrl)
  })

  it('keeps a percent-encoded space id segment encoded', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const spaceUrl = spaceUrlFor('a/b')
    await client.revoke(
      delegatedZcap({
        rootId: rootCapabilityId(spaceUrl),
        invocationTarget: `${spaceUrl}notes/`
      })
    )

    expect(lastRequest()?.url).toBe(
      `https://was.example/space/a%2Fb/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('posts to a Space on another origin, as its chain names it', async () => {
    // The client is built for one server, but a capability names its own
    // Space: the revocation goes where the chain points.
    const { client, lastRequest } = clientWithRequestSpy()
    const spaceUrl = 'https://elsewhere.example/space/space-1/'
    await client.revoke(
      delegatedZcap({
        rootId: rootCapabilityId(spaceUrl),
        invocationTarget: `${spaceUrl}notes/`
      })
    )

    expect(lastRequest()?.url).toBe(
      `${spaceUrl}zcaps/revocations/${encodeURIComponent(CAPABILITY_ID)}`
    )
  })

  it('keeps a path prefix the Space URL carries', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const spaceUrl = 'https://host.example/was/space/space-1/'
    await client.revoke(
      delegatedZcap({
        rootId: rootCapabilityId(spaceUrl),
        invocationTarget: `${spaceUrl}notes/`
      })
    )

    expect(lastRequest()?.url).toBe(
      'https://host.example/was/space/space-1/zcaps/revocations/' +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('rejects a chain that does not start at a root capability id', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    for (const chain of ['proof', 'parent'] as const) {
      await expect(
        client.revoke(delegatedZcap({ rootId: 'urn:uuid:not-a-root', chain }))
      ).rejects.toThrow(/not rooted in a Space/)
    }
    expect(lastRequest()).toBeUndefined()
  })

  it('rejects a root capability that names no Space URL', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    for (const target of ['did:example:alice']) {
      await expect(
        client.revoke(delegatedZcap({ rootId: rootCapabilityId(target) }))
      ).rejects.toThrow(ValidationError)
    }
    expect(lastRequest()).toBeUndefined()
  })

  it('refuses a root capability, before any request', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const root = {
      '@context': 'https://w3id.org/zcap/v1',
      id: rootCapabilityId(SPACE_URL),
      invocationTarget: SPACE_URL,
      controller: 'did:example:alice'
    } as unknown as IDelegatedZcap

    await expect(client.revoke(root)).rejects.toThrow(ValidationError)
    expect(lastRequest()).toBeUndefined()
  })
})
