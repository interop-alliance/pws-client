/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `ensureSpace` and `ensureSpaceAndCollection` against a live
 * PWS server. The fakes tier covers the two halves separately, each against a
 * hand-written description. This suite pins what no fake can assert: a served
 * Space description carries `id`, so the description `ensureSpace` returns can
 * be handed straight to `ensureSpaceAndCollection`, on the first pass and on
 * the already-provisioned second pass alike.
 *
 * Requires a running server: `TEST_SERVER_URL`, which the global setup sets
 * when it boots one in-process.
 */
import { describe, it, beforeAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { PwsClient } from '../../src/index.js'
import { ensureSpace, ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

describeLive('sync provisioning (live server)', () => {
  let pws: PwsClient
  let spaceId: string
  let spaceUrl: string

  beforeAll(async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    pws = PwsClient.fromSigner({
      baseServerUrl: baseServerUrl!,
      signer: keyPair.didKeySigner()
    })
    spaceId = crypto.randomUUID()
    spaceUrl = pws.space(spaceId).url
  })

  it('ensureSpace creates the Space and returns the served description with its id', async () => {
    const description = await ensureSpace({
      pws,
      spaceUrl,
      controllerDid: pws.controllerDid,
      spaceName: 'Provisioning Integration'
    })
    expect(description.id).toBe(spaceId)
    expect(description.controller).toBe(pws.controllerDid)
    expect(description.name).toBe('Provisioning Integration')

    const served = await pws.spaceAt(spaceUrl).describe()
    expect(served).toEqual(description)
  })

  it('ensureSpace on the existing Space returns the same served description', async () => {
    const description = await ensureSpace({
      pws,
      spaceUrl,
      controllerDid: pws.controllerDid,
      spaceName: 'A name the existing Space keeps ignoring'
    })
    expect(description.id).toBe(spaceId)
    expect(description.name).toBe('Provisioning Integration')
  })

  it('ensureSpaceAndCollection accepts the description ensureSpace returned', async () => {
    const spaceDescription = await ensureSpace({
      pws,
      spaceUrl,
      controllerDid: pws.controllerDid
    })
    const first = await ensureSpaceAndCollection({
      pws,
      spaceUrl,
      controllerDid: pws.controllerDid,
      collectionId: 'vault',
      spaceDescription
    })
    expect(first).toEqual({ created: true })

    const vault = await pws.spaceAt(spaceUrl).collection('vault').describe()
    expect(vault?.encryption).toMatchObject({ version: EDV_SCHEME_VERSION })

    // The already-provisioned pass: same served description, nothing created.
    const second = await ensureSpaceAndCollection({
      pws,
      spaceUrl,
      controllerDid: pws.controllerDid,
      collectionId: 'vault',
      spaceDescription: await ensureSpace({
        pws,
        spaceUrl,
        controllerDid: pws.controllerDid
      })
    })
    expect(second).toEqual({ created: false })
  })

  it('ensureSpaceAndCollection without a description provisions both halves itself', async () => {
    const otherSpaceId = crypto.randomUUID()
    const otherSpaceUrl = pws.space(otherSpaceId).url
    const first = await ensureSpaceAndCollection({
      pws,
      spaceUrl: otherSpaceUrl,
      controllerDid: pws.controllerDid,
      collectionId: 'notes',
      encryption: 'plaintext'
    })
    expect(first).toEqual({ created: true })
    const served = await pws.spaceAt(otherSpaceUrl).describe()
    expect(served?.id).toBe(otherSpaceId)

    const second = await ensureSpaceAndCollection({
      pws,
      spaceUrl: otherSpaceUrl,
      controllerDid: pws.controllerDid,
      collectionId: 'notes',
      encryption: 'plaintext'
    })
    expect(second).toEqual({ created: false })
  })
})
