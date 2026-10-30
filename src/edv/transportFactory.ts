/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `pwsTransportFactory`: the one function that constructs a {@link
 * PwsTransport} for an {@link EdvCodec}. It lives apart from the codec class
 * because it is the codec's only reach to a server: the class itself takes its
 * transport through the injected `CodecTransportFactory` seam, so a build with
 * no server behind it (the local-replica doc cipher) never evaluates this
 * module, nor the transport and request machinery behind it.
 */
import { PwsTransport } from './PwsTransport.js'
import type { CodecTransportFactory } from './EdvCodec.js'

/**
 * Builds the transport factory for a Collection reachable over PWS: the
 * codec's route to its own document and chunk resources on the server.
 *
 * @param options {object}
 * @param options.spaceUrl {string}       the Space holding the Collection
 * @param options.collectionId {string}   the Collection
 * @param options.contentType {string}    stored envelope content type
 * @returns {CodecTransportFactory}
 */
export function pwsTransportFactory({
  spaceUrl,
  collectionId,
  contentType
}: {
  spaceUrl: string
  collectionId: string
  contentType: string
}): CodecTransportFactory {
  return ({ context, documentHeaders, baseline }) =>
    new PwsTransport({
      pws: { request: input => context.request(input) },
      spaceUrl,
      collectionId,
      contentType,
      ...(documentHeaders !== undefined && { documentHeaders }),
      ...(baseline !== undefined && { baseline })
    })
}
