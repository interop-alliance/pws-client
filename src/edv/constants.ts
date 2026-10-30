/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared EDV-over-PWS constants: the scheme version of the envelope wire
 * format, the stored-envelope content types (the portable default and the
 * preferred JOSE type), and the envelope byte serialization. Kept in one place
 * so `PwsTransport` and `EdvCodec` stay in lockstep instead of each declaring
 * their own copy.
 */
import { ENCODER } from '../internal/content.js'

/**
 * The EDV-over-PWS scheme version: the version of the envelope wire format
 * this package's cipher writes, as registered in the PWS spec's Encryption
 * Scheme Registry (a positive integer with a total order, not a semantic
 * version; an absent `version` on a descriptor means `1`). This is the ONLY
 * place the number is declared: the collection `encryption` descriptor PUTs
 * stamp it, and the cipher binds the same constant into every envelope's
 * AEAD-protected `pws.v` header parameter, so the descriptor and the envelopes
 * can never disagree.
 */
export const EDV_SCHEME_VERSION = 1

/**
 * The content type used by default: plain JSON, which an unmodified PWS server
 * accepts. The stored envelope is still self-identifying by its `jwe` field.
 */
export const DEFAULT_CONTENT_TYPE = 'application/json'

/**
 * The preferred content type marking a stored EDV-encrypted document: the JWE
 * JSON Serialization media type (`application/jose+json`, RFC 7516), which is
 * the wire format the PWS spec's Encryption Scheme Registry maps the `edv`
 * scheme to. The stored envelope's `jwe` property carries the ciphertext.
 * Requires the server to register an `application/*+json` content-type parser;
 * otherwise use the default `application/json` (see `PwsTransport`'s
 * `contentType` option).
 */
export const JOSE_CONTENT_TYPE = 'application/jose+json'

/**
 * Serializes an encrypted envelope to its wire bytes -- the single source of
 * the envelope encoding shared by `EdvCodec` and `PwsTransport`.
 *
 * @param envelope {object}   the encrypted EDV document envelope
 * @returns {Uint8Array}
 */
export function envelopeBytes(envelope: object): Uint8Array {
  return ENCODER.encode(JSON.stringify(envelope))
}
