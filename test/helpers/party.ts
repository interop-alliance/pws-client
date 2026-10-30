/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared party fixtures for the live-server encryption suites: a
 * self-describing `did:key` X25519 key-agreement key, and a party built around
 * one -- an Ed25519 signer for authorization plus an encryption-capable
 * `PwsClient` over both.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { PwsClient } from '../../src/index.js'
import type { EncryptionProvider } from '../../src/index.js'
import { createEdvEncryption } from '../../src/edv/index.js'
import { didKeyResolver } from '../../src/edv/epochCrypto.js'

export interface Party {
  pws: PwsClient
  provider: EncryptionProvider
  signer: Parameters<typeof PwsClient.fromSigner>[0]['signer']
  did: string
  kak: IKeyAgreementKey
  recipient: { id: string; publicKeyMultibase: string }
}

/**
 * Generates a self-describing `did:key` X25519 key-agreement key: its `id` is
 * `did:key:<pub>#<pub>`, so the default `did:key` recipient resolver recovers
 * its public key from the `kid` alone -- what `removeRecipient` re-wraps the
 * fresh epoch to.
 *
 * @returns {Promise<{ kak: IKeyAgreementKey;
 *   recipient: { id: string; publicKeyMultibase: string } }>}
 */
export async function makeDidKeyKak(): Promise<{
  kak: IKeyAgreementKey
  recipient: { id: string; publicKeyMultibase: string }
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return {
    kak: kak as IKeyAgreementKey,
    recipient: { id: kak.id, publicKeyMultibase: kak.publicKeyMultibase }
  }
}

/**
 * Builds a party: an Ed25519 signer (for authorization) plus a self-describing
 * `did:key` X25519 key-agreement key (for decryption), and a `PwsClient` whose
 * encryption provider supplies that X25519 key.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}   the server's base server URL
 * @returns {Promise<Party>}
 */
export async function makeParty({
  baseServerUrl
}: {
  baseServerUrl: string
}): Promise<Party> {
  const keyPair = await Ed25519VerificationKey.generate()
  const { kak, recipient } = await makeDidKeyKak()
  const provider = createEdvEncryption({
    resolveKeys: async () => ({
      keyAgreementKey: kak,
      keyResolver: didKeyResolver
    })
  })
  const signer = keyPair.didKeySigner()
  return {
    pws: PwsClient.fromSigner({ baseServerUrl, signer, encryption: provider }),
    provider,
    signer,
    did: `did:key:${keyPair.fingerprint()}`,
    kak,
    recipient
  }
}
