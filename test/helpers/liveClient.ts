/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared client fixture for the live-server integration suites: a `PwsClient`
 * over a fresh did:key Ed25519 signer, bound to the server `TEST_SERVER_URL`
 * names.
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { PwsClient } from '../../src/index.js'

/**
 * Builds a fresh did:key Ed25519 signer and a PWS client over it. The signer's
 * DID is the client's `controllerDid`.
 *
 * @returns {Promise<PwsClient>}
 */
export async function freshPwsClient(): Promise<PwsClient> {
  const keyPair = await Ed25519VerificationKey.generate()
  return PwsClient.fromSigner({
    baseServerUrl: process.env.TEST_SERVER_URL!,
    signer: keyPair.didKeySigner()
  })
}
