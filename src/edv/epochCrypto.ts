/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The key-epoch cryptography for multi-recipient encrypted Collections: wrapping
 * and unwrapping a per-epoch collection key to each reader's X25519
 * key-agreement key, and minting / reconstructing the epoch key pair the EDV
 * codec encrypts resources under.
 *
 * A collection key epoch is a fresh 32-byte X25519 private key. Resources are
 * encrypted with the ordinary EDV `documentCipher`, naming the epoch's public
 * key as the sole recipient (each document gets a fresh content-encryption key
 * wrapped `ECDH-ES+A256KW` to the epoch key) -- so the read/write machinery is
 * unchanged and only key resolution is epoch-aware. The epoch's public key IS
 * its `did:key`, and the epoch id is that `did:key` string, so the standard
 * `did:key` resolver resolves the recipient named in a resource's JWE.
 *
 * The epoch key itself is shared with a reader by wrapping the 32-byte epoch
 * secret to the reader's own X25519 key-agreement key, `ECDH-ES+A256KW`, and
 * storing the result as a JWE `recipients` entry verbatim on the Collection's
 * `encryption` descriptor. The wrap is derive-then-wrap per recipient: an
 * ephemeral ECDH against the reader's public key, the RFC 7518 Concat KDF, then
 * A256KW -- `@interop/minimal-cipher`'s own `ECDH-ES+A256KW` building blocks
 * (via its `algorithms` subpath), so the wrapped bytes are interchangeable with
 * what its `Cipher` would produce.
 *
 * The two axes stay separate here: this module governs **read** (who can
 * decrypt), which is prospective -- rotating the epoch only protects resources
 * written afterwards. **Pull** (who the server will serve ciphertext to) is the
 * zcap layer, enforced immediately at request time. Neither alone removes a
 * reader; see `removeRecipient`.
 */
import { base64urlnopad } from '@scure/base'
import { createKek, deriveKey } from '@interop/minimal-cipher/algorithms'
import {
  X25519KeyAgreementKey2020,
  multibaseDecode,
  multibaseEncode,
  MULTICODEC_X25519_PUB_HEADER
} from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { IntegrityError } from '../errors.js'
import { ENCODER } from '../internal/content.js'
import type { CollectionEncryptionRecipient } from '../types.js'

/**
 * The JOSE key-management algorithm for every epoch/recipient wrap.
 */
const KEY_WRAP_ALG = 'ECDH-ES+A256KW'

/**
 * The X25519 suite tag used for the ephemeral and reconstructed key pairs.
 */
const X25519_TYPE = 'X25519KeyAgreementKey2020'

/**
 * The `did:key` method prefix. An epoch id IS a `did:key`, so this module owns
 * the grammar: it mints ids with the prefix, strips it back off to recover the
 * public key fingerprint, and `didKeyRecipient` reuses it to recognize the
 * controller DIDs it can derive a recipient key from.
 */
export const DID_KEY_PREFIX = 'did:key:'

/**
 * A reader's public key-agreement key, as needed to wrap an epoch key to it:
 * the recipient `id` (`kid`, which the reader's own key-agreement key must also
 * report) and its `publicKeyMultibase`.
 */
export interface RecipientPublicKey {
  id: string
  publicKeyMultibase: string
  type?: string
}

/**
 * Wraps a 32-byte epoch secret to one recipient's X25519 key-agreement key,
 * producing the JWE `recipients` entry stored on the descriptor. Generates a
 * fresh ephemeral key per call (ECDH-ES), so each wrap carries its own `epk`.
 *
 * @param options {object}
 * @param options.epochSecret {Uint8Array}       the 32-byte epoch key to wrap
 * @param options.recipient {RecipientPublicKey}   the reader's public KAK
 * @returns {Promise<CollectionEncryptionRecipient>}
 */
export async function wrapEpochSecret({
  epochSecret,
  recipient
}: {
  epochSecret: Uint8Array
  recipient: RecipientPublicKey
}): Promise<CollectionEncryptionRecipient> {
  const ephemeral = await X25519KeyAgreementKey2020.generate()
  const ephemeralPublicKey = multibaseDecode(
    MULTICODEC_X25519_PUB_HEADER,
    ephemeral.publicKeyMultibase
  )
  const secret = await ephemeral.deriveSecret({
    publicKey: { publicKeyMultibase: recipient.publicKeyMultibase }
  })
  const producerInfo = ephemeralPublicKey
  const consumerInfo = ENCODER.encode(recipient.id)
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  const kek = await createKek({ keyData })
  const encryptedKey = await kek.wrapKey({ unwrappedKey: epochSecret })
  return {
    header: {
      kid: recipient.id,
      alg: KEY_WRAP_ALG,
      epk: {
        kty: 'OKP',
        crv: 'X25519',
        x: base64urlnopad.encode(ephemeralPublicKey)
      },
      apu: base64urlnopad.encode(producerInfo),
      apv: base64urlnopad.encode(consumerInfo)
    },
    encrypted_key: encryptedKey
  }
}

/**
 * Wraps one epoch secret to each of several readers, concurrently: the fan-out
 * behind every roster mint and escrow, so each recipient entry is produced by
 * {@link wrapEpochSecret} and nothing else.
 *
 * @param options {object}
 * @param options.epochSecret {Uint8Array}
 * @param options.recipients {RecipientPublicKey[]}
 * @returns {Promise<CollectionEncryptionRecipient[]>}   one entry per reader, in
 *   input order
 */
export async function wrapEpochSecretTo({
  epochSecret,
  recipients
}: {
  epochSecret: Uint8Array
  recipients: RecipientPublicKey[]
}): Promise<CollectionEncryptionRecipient[]> {
  return Promise.all(
    recipients.map(recipient => wrapEpochSecret({ epochSecret, recipient }))
  )
}

/**
 * Unwraps an epoch secret from a descriptor `recipients` entry using the
 * reader's own key-agreement key. Returns `null` when the entry is not
 * addressed to this key (its `kid` is another reader's id) or is malformed (no
 * usable `epk`, a non-base64url `encrypted_key`, a failed ECDH) -- never treat
 * `null` as a key; try the next candidate entry or epoch, and fail with a
 * typed error when nothing unwraps.
 *
 * Throws {@link IntegrityError} when the entry names this reader and is
 * well-formed but its AES-KW integrity check fails. That cannot mean "not my
 * entry": the entry is addressed to this reader and its wrapped bytes do not
 * authenticate under the key they were wrapped to. It is the key-wrap
 * counterpart of a content envelope whose AEAD tag fails for a kid-matched
 * key, and it is reported the same way rather than as a membership decision.
 *
 * @param options {object}
 * @param options.entry {CollectionEncryptionRecipient}   the descriptor entry
 * @param options.keyAgreementKey {IKeyAgreementKey}      the reader's own KAK
 *   (its `id` must equal `entry.header.kid` for the derivation to match)
 * @returns {Promise<Uint8Array | null>}
 */
export async function unwrapEpochSecret({
  entry,
  keyAgreementKey
}: {
  entry: CollectionEncryptionRecipient
  keyAgreementKey: IKeyAgreementKey
}): Promise<Uint8Array | null> {
  if (entry.header.kid !== keyAgreementKey.id) {
    // Another reader's entry: the KDF binds the wrap to the recipient's key
    // id, so this key could never unwrap it, and a failure below would say
    // nothing about the entry's integrity.
    return null
  }
  const epk = entry.header.epk as { x?: unknown } | undefined
  if (!epk || typeof epk.x !== 'string') {
    return null
  }
  let ephemeralPublicKey: Uint8Array
  try {
    ephemeralPublicKey = base64urlnopad.decode(epk.x)
  } catch {
    // A malformed (non-base64url) `epk.x` is the malformed-entry class:
    // honor the documented null contract.
    return null
  }
  let secret: Uint8Array
  try {
    secret = await keyAgreementKey.deriveSecret({
      publicKey: {
        type: X25519_TYPE,
        publicKeyMultibase: multibaseEncode(
          MULTICODEC_X25519_PUB_HEADER,
          ephemeralPublicKey
        )
      }
    })
  } catch {
    return null
  }
  const producerInfo = ephemeralPublicKey
  const consumerInfo = ENCODER.encode(keyAgreementKey.id)
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  const kek = await createKek({ keyData })
  let unwrapped: Uint8Array | null
  try {
    unwrapped = await kek.unwrapKey({ wrappedKey: entry.encrypted_key })
  } catch {
    // `unwrapKey` throws on a malformed (non-base64url or wrong-length)
    // `encrypted_key`: the malformed-entry class, so honor the documented
    // null contract.
    return null
  }
  if (unwrapped === null) {
    // `unwrapKey` returns null only when the bytes decoded and had a valid
    // length but the AES-KW integrity check failed: the entry is addressed to
    // this reader and does not authenticate under its key.
    throw new IntegrityError(
      `This reader's recipient entry (kid "${entry.header.kid}") failed to ` +
        'authenticate: its wrapped epoch key did not pass the AES-KW ' +
        'integrity check. The entry names this reader, so this is not a ' +
        'membership problem -- the stored entry is corrupt or has been ' +
        'tampered with.'
    )
  }
  return unwrapped
}

/**
 * Mints a fresh key epoch: a new random X25519 key pair whose `did:key` is the
 * epoch id. Returns the id and the raw 32-byte secret (to wrap to recipients);
 * `resolveEpochKeys` reconstructs the epoch key pair from the id and secret when
 * a resource must be encrypted or decrypted under the epoch.
 *
 * @returns {Promise<{ epochId: string, secret: Uint8Array }>}
 */
export async function mintEpoch(): Promise<{
  epochId: string
  secret: Uint8Array
}> {
  const generated = await X25519KeyAgreementKey2020.generate()
  if (generated.privateKeyMultibase === undefined) {
    throw new Error('Generated epoch key is missing its private key.')
  }
  const secret = generated.rawSecret
  const epochId = `${DID_KEY_PREFIX}${generated.publicKeyMultibase}`
  return { epochId, secret }
}

/**
 * Reconstructs an epoch key pair from its id (a `did:key`, which carries the
 * public key) and the unwrapped 32-byte secret, ready to hand to the EDV
 * `documentCipher` as its `keyAgreementKey`.
 *
 * @param options {object}
 * @param options.epochId {string}      the epoch's `did:key`
 * @param options.secret {Uint8Array}   the unwrapped 32-byte epoch secret
 * @returns {X25519KeyAgreementKey2020}
 */
export function reconstructEpochKeyPair({
  epochId,
  secret
}: {
  epochId: string
  secret: Uint8Array
}): IKeyAgreementKey {
  // The concrete instance always carries a defined `id` (set here), so it
  // satisfies `IKeyAgreementKey` (whose `id` is required); the suite's type
  // declares `id` optional, hence the assertion.
  return X25519KeyAgreementKey2020.fromRawSecret({
    secret,
    controller: epochId,
    id: epochKeyIdFor(epochId)
  }) as IKeyAgreementKey
}

/**
 * The verification-method id of an epoch key: `<did:key>#<fingerprint>`. This is
 * the `kid` the EDV `documentCipher` stamps on a resource encrypted under the
 * epoch; a reader maps it back to the epoch by taking the `did:key` portion
 * before the `#` fragment.
 *
 * @param epochId {string}   the epoch's `did:key`
 * @returns {string}
 */
export function epochKeyIdFor(epochId: string): string {
  return `${epochId}#${publicKeyMultibaseFromEpochId(epochId)}`
}

/**
 * Extracts the `publicKeyMultibase` fingerprint from an epoch id
 * (`did:key:z...`).
 *
 * @param epochId {string}
 * @returns {string}
 */
function publicKeyMultibaseFromEpochId(epochId: string): string {
  if (!epochId.startsWith(DID_KEY_PREFIX)) {
    throw new Error(
      `Epoch id "${epochId}" is not a did:key (expected a ` +
        `"${DID_KEY_PREFIX}z..." id).`
    )
  }
  return epochId.slice(DID_KEY_PREFIX.length)
}

/**
 * Memo of already-resolved key ids: the resolution is a pure deterministic
 * function of the id, and the write path resolves the same epoch key on every
 * encode, so each distinct id pays the fingerprint reconstruction once. Grows
 * by one small entry per distinct epoch/recipient key seen in the process.
 */
const RESOLVED_KEYS = new Map<
  string,
  { id: string; type: string; publicKeyMultibase: string }
>()

/**
 * A `did:key` key resolver for X25519 key-agreement keys: resolves a
 * `did:key:z...#z...` id (an epoch key, or any self-describing X25519 key) to
 * its public verification method. The public key is the fragment, so no network
 * or registry lookup is needed. Memoized per id.
 *
 * @param options {object}
 * @param options.id {string}   the key id to resolve
 * @returns {Promise<{ id: string, type: string, publicKeyMultibase: string }>}
 */
export async function didKeyResolver({
  id
}: {
  id?: string
}): Promise<{ id: string; type: string; publicKeyMultibase: string }> {
  if (!id) {
    throw new Error('A key id is required to resolve.')
  }
  const cached = RESOLVED_KEYS.get(id)
  if (cached) {
    return cached
  }
  const hash = id.indexOf('#')
  const fragment = hash === -1 ? '' : id.slice(hash + 1)
  if (!fragment.startsWith('z')) {
    throw new Error(`Cannot resolve non-did:key key id "${id}".`)
  }
  // Validate the fragment is a well-formed X25519 public key fingerprint; the
  // suite throws on invalid header bytes.
  const keyPair = X25519KeyAgreementKey2020.fromFingerprint({
    fingerprint: fragment
  })
  keyPair.verifyFingerprint({ fingerprint: fragment })
  const resolved = {
    id,
    type: X25519_TYPE,
    publicKeyMultibase: keyPair.publicKeyMultibase
  }
  RESOLVED_KEYS.set(id, resolved)
  return resolved
}
