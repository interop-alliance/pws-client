/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Live-server fixtures for the chunked-stream integration tests: a WAS client
 * whose EDV provider routes anything over a small threshold to the
 * chunked-stream path, an encrypted Collection provisioned for it, and a probe
 * that reads one stored chunk straight off the server, past the codec, to
 * observe which path a write took.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { httpStatus, WasClient } from '../../src/index.js'
import type { Collection, Space } from '../../src/index.js'
import { resourceChunkUrl } from '../../src/internal/paths.js'
import {
  createEdvEncryption,
  ensureFirstEpoch,
  ownerRecipient
} from '../../src/edv/index.js'

/**
 * Builds a WAS client whose EDV provider routes anything over `maxBlobBytes`
 * to the chunked-stream path, plus the key-agreement key the collection's
 * first epoch is wrapped to.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}   the server's base server URL
 * @param options.maxBlobBytes {number}   the routing threshold
 * @param options.chunkSize {number}      the size of each encrypted chunk
 * @returns {Promise<{ was: WasClient; kak: IKeyAgreementKey }>}
 */
export async function chunkedClient({
  baseServerUrl,
  maxBlobBytes,
  chunkSize
}: {
  baseServerUrl: string
  maxBlobBytes: number
  chunkSize: number
}): Promise<{ was: WasClient; kak: IKeyAgreementKey }> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`

  const kak = await X25519KeyAgreementKey2020.generate({ controller: did })
  const keyResolver = async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }
  const encryption = createEdvEncryption({
    resolveKeys: async () => ({
      keyAgreementKey: kak as IKeyAgreementKey,
      keyResolver
    }),
    maxBlobBytes,
    chunkSize
  })
  return {
    was: WasClient.fromSigner({
      baseServerUrl,
      signer: keyPair.didKeySigner(),
      encryption
    }),
    kak: kak as IKeyAgreementKey
  }
}

/**
 * Creates a Space holding an encrypted Collection `vault` whose first epoch
 * is wrapped to `kak`, and returns the Space with a handle on the Collection
 * bound to the client's encryption provider.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.kak {IKeyAgreementKey}
 * @param options.name {string}   the Space name
 * @returns {Promise<{ space: Space; collection: Collection }>}
 */
export async function provisionVault({
  was,
  kak,
  name
}: {
  was: WasClient
  kak: IKeyAgreementKey
  name: string
}): Promise<{ space: Space; collection: Collection }> {
  const space = await was.createSpace({ name })
  const declared = await space.createCollection({
    id: 'vault',
    name: 'Vault',
    encryption: { scheme: 'edv' }
  })
  await ensureFirstEpoch({
    collection: declared,
    recipients: [ownerRecipient({ keyAgreementKey: kak })]
  })
  return { space, collection: was.spaceAt(space.url).collection('vault') }
}

/**
 * Reads one stored chunk resource of `resourceId` in Collection `vault`
 * straight off the server, past the codec, to observe which path the write
 * took. The raw escape hatch throws on a 404, so the status comes off the
 * error in that case.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceUrl {string}
 * @param options.resourceId {string}
 * @param options.chunkIndex {number}
 * @returns {Promise<number | undefined>}   the response status
 */
export async function chunkStatus({
  was,
  spaceUrl,
  resourceId,
  chunkIndex
}: {
  was: WasClient
  spaceUrl: string
  resourceId: string
  chunkIndex: number
}): Promise<number | undefined> {
  try {
    const response = await was.request({
      url: resourceChunkUrl({
        spaceUrl,
        collectionId: 'vault',
        resourceId,
        chunkIndex
      }),
      method: 'GET'
    })
    return response.status
  } catch (err) {
    return httpStatus(err)
  }
}
