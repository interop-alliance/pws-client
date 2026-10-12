/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared reader fixtures for the EDV tests: a real X25519 key-agreement key
 * with its resolver, and the single-epoch `edv` descriptor an encrypted
 * collection carries from birth. Pure and browser-safe, so the Playwright
 * fixtures use them too.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/index.js'
import { ownerRecipient } from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'

/**
 * A fresh real X25519 key-agreement key plus a resolver that returns it.
 *
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey;
 *   keyResolver: IKeyResolver }>}
 */
export async function makeKeys(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyResolver = (async ({ id }: { id?: string }) => {
    if (id !== kak.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    }
  }) as unknown as IKeyResolver
  return { keyAgreementKey: kak as unknown as IKeyAgreementKey, keyResolver }
}

/**
 * Builds the single-epoch `edv` descriptor an encrypted collection carries from
 * birth, wrapping one freshly-minted epoch key to every given reader.
 *
 * @param readers {IKeyAgreementKey[]}   the recipients of epoch zero
 * @returns {Promise<CollectionEncryption>}
 */
export async function epochDescriptorFor(
  readers: IKeyAgreementKey[]
): Promise<CollectionEncryption> {
  const { epochId, secret } = await mintEpoch()
  const recipients: CollectionEncryptionRecipient[] = []
  for (const keyAgreementKey of readers) {
    recipients.push(
      await wrapEpochSecret({
        epochSecret: secret,
        recipient: ownerRecipient({ keyAgreementKey })
      })
    )
  }
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [{ id: epochId, recipients }],
    currentEpoch: epochId
  }
  return encryption
}

/**
 * A fresh reader plus the single-epoch descriptor it is recipient zero of --
 * the whole input a cipher or an encrypted-collection codec is built from.
 *
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey;
 *   keyResolver: IKeyResolver; encryption: CollectionEncryption }>}
 */
export async function makeReaderWithDescriptor(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  encryption: CollectionEncryption
}> {
  const keys = await makeKeys()
  return {
    ...keys,
    encryption: await epochDescriptorFor([keys.keyAgreementKey])
  }
}
