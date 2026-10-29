/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: service discovery against a live WAS server. The client
 * follows the `rel="service"` link from the server's responses, selects the
 * v0.5 entry, and creates and lists a Space at the Spaces Repository URL the
 * document names.
 *
 * Requires a running server: set `TEST_SERVER_URL` to the server's base server
 * URL. Its origin must be byte-identical to the server's own
 * `SERVER_URL` (zcap invocation targets embed host and port). The suite skips
 * when `TEST_SERVER_URL` is unset.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import {
  IncompatibleServerError,
  WasClient,
  discoverService
} from '../../src/index.js'
import {
  serviceDescriptionUrl,
  spacesRepositoryUrl,
  spaceUrlById
} from '../../src/paths.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

/**
 * Builds a WAS client over a fresh did:key Ed25519 signer.
 *
 * @returns {Promise<WasClient>}
 */
async function freshWasClient(): Promise<WasClient> {
  const keyPair = await Ed25519VerificationKey.generate()
  return WasClient.fromSigner({
    baseServerUrl: baseServerUrl!,
    signer: keyPair.didKeySigner()
  })
}

describeLive('service discovery (live server)', () => {
  it('discovers the service description and selects v0.5', async () => {
    const was = await freshWasClient()
    const info = await was.service()
    expect(info.version).toBe('0.5')
    expect(new URL(info.description.url).origin).toBe(
      new URL(baseServerUrl!).origin
    )
    expect(info.spacesUrl).toEqual(expect.any(String))
    expect(info.hasFeature('listing')).toBe(true)
  })

  it('agrees with the base: the description names {base}service and {base}spaces/', async () => {
    const was = await freshWasClient()
    expect(was.baseServerUrl).toBe(baseServerUrl)
    const info = await was.service()
    expect(info.description.url).toBe(
      serviceDescriptionUrl({ baseServerUrl: baseServerUrl! })
    )
    expect(info.spacesUrl).toBe(
      spacesRepositoryUrl({ baseServerUrl: baseServerUrl! })
    )
  })

  it('a wrong base rejects with IncompatibleServerError (the server answers 404 at {base}service)', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const was = WasClient.fromSigner({
      baseServerUrl: `${baseServerUrl}nope/`,
      signer: keyPair.didKeySigner()
    })
    await expect(was.service()).rejects.toThrow(IncompatibleServerError)
  })

  it('discovers from a 404 on a URL the client holds', async () => {
    // Discovery probes whatever URL the client has, which may be a resource
    // that does not exist: the `rel="service"` link rides on the 404 too.
    const info = await discoverService({
      url: `${spaceUrlById({ baseServerUrl: baseServerUrl!, spaceId: 'no-such-space' })}c/r`
    })
    expect(info.version).toBe('0.5')
    expect(new URL(info.description.url).origin).toBe(
      new URL(baseServerUrl!).origin
    )
  })

  it('creates and lists a Space at the advertised Spaces Repository URL', async () => {
    const was = await freshWasClient()
    const space = await was.createSpace({ name: 'Service Discovery' })
    const listing = await was.listSpaces()
    expect(listing.items.map(item => item.id)).toContain(space.id)
    await space.delete()
    // Space creation, listing, and deletion run past the 5s default when the
    // rest of the integration tier loads the same server in parallel.
  }, 30_000)

  it('lists every Space with its type array, auxiliary Spaces included', async () => {
    const was = await freshWasClient()
    const [data, auxiliary] = await Promise.all([
      was.createSpace({ name: 'Data' }),
      was.createSpace({ name: 'Clients', type: ['AuxiliarySpace', 'Space'] })
    ])
    try {
      const { items } = await was.listSpaces()
      expect(items.find(item => item.id === data.id)?.type).toEqual(['Space'])
      expect(items.find(item => item.id === auxiliary.id)?.type).toEqual([
        'AuxiliarySpace',
        'Space'
      ])
    } finally {
      await Promise.all([data.delete(), auxiliary.delete()])
    }
  }, 30_000)
})
