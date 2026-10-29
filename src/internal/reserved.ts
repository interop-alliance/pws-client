/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reserved path-segment registry and the client-side id-collision guard.
 * Rejecting reserved ids up front (with a clear `ValidationError`) is friendlier
 * than letting the server answer `409 Conflict`.
 *
 * The reserved sets themselves are single-sourced from `@interop/storage-core`
 * (the spec's Reserved Path Segment Registry). This module adds the
 * client-side `ValidationError`-throwing guard and the two membership
 * predicates the path grammar asks with.
 */
import {
  ORIGIN_ROOT_RESERVED_COLLECTION_IDS,
  RESERVED_COLLECTION_IDS,
  RESERVED_RESOURCE_IDS
} from '@interop/storage-core'

import { ValidationError } from '../errors.js'

/**
 * Whether `id` is a reserved Collection-id path segment. At a Space served
 * from an origin root the Collection id is the first path segment, where a
 * server with a base server URL places its server-level endpoints, so the
 * spec reserves those segments there too (and only there).
 *
 * @param id {string}
 * @param options {object}
 * @param [options.originRoot] {boolean}   whether the Space is served from an
 *   origin root
 * @returns {boolean}
 */
export function isReservedCollectionId(
  id: string,
  { originRoot = false }: { originRoot?: boolean } = {}
): boolean {
  return (
    RESERVED_COLLECTION_IDS.has(id) ||
    (originRoot && isOriginRootReservedCollectionId(id))
  )
}

/**
 * Whether `id` is one of the server-level endpoint segments (`service`,
 * `spaces`, `space`), reserved as a Collection id only at a Space served
 * from an origin root.
 *
 * @param id {string}
 * @returns {boolean}
 */
function isOriginRootReservedCollectionId(id: string): boolean {
  return ORIGIN_ROOT_RESERVED_COLLECTION_IDS.has(id)
}

/**
 * Whether `id` is a reserved Resource-id path segment.
 *
 * @param id {string}
 * @returns {boolean}
 */
export function isReservedResourceId(id: string): boolean {
  return RESERVED_RESOURCE_IDS.has(id)
}

/**
 * Throws a `ValidationError` if the given id collides with a reserved path
 * segment for its kind.
 *
 * @param options {object}
 * @param options.id {string}     the proposed collection or resource id
 * @param options.kind {string}   'collection' or 'resource', selects the
 *   reserved set and is used in the message
 * @param [options.originRoot] {boolean}   whether the Space is served from an
 *   origin root, where the server-level endpoint segments are reserved as
 *   Collection ids too
 * @returns {void}
 */
export function assertNotReserved({
  id,
  kind,
  originRoot = false
}: {
  id: string
  kind: 'collection' | 'resource'
  originRoot?: boolean
}): void {
  const reserved =
    kind === 'collection'
      ? isReservedCollectionId(id, { originRoot })
      : isReservedResourceId(id)
  if (!reserved) {
    return
  }
  // The origin-root-only ids are reserved for a reason the plain message
  // would not convey.
  const where =
    RESERVED_COLLECTION_IDS.has(id) || kind === 'resource'
      ? ''
      : ' at a Space served from an origin root'
  throw new ValidationError(
    `Cannot use reserved path segment "${id}" as a ${kind} id${where}.`
  )
}
