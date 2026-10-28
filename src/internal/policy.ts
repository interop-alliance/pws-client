/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared access-control policy I/O for the Space / Collection / Resource
 * handles, which differ only in the policy sub-resource URL. Each handle wraps
 * these with its own JSDoc and the trivial `isPublic` / `setPublic` sugar.
 */
import type { ClientContext } from './request.js'
import { readData, readDataWithEtag, send } from './request.js'
import { readEtag, writeHeaders } from './conditional.js'
import type { WritePrecondition } from './conditional.js'
import type { IZcap, PolicyDocument } from '../types.js'

/**
 * Reads the access-control policy at `policyUrl` together with its `ETag`
 * validator. Returns `null` when no policy is set (or it is not visible to
 * you); `etag` is absent only where the header did not reach the client.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param [options.capability] {IZcap}
 * @returns {Promise<{ policy: PolicyDocument; etag?: string } | null>}
 */
export async function readPolicyWithEtag(
  context: ClientContext,
  { policyUrl, capability }: { policyUrl: string; capability?: IZcap }
): Promise<{ policy: PolicyDocument; etag?: string } | null> {
  const read = await readDataWithEtag<PolicyDocument>(context, {
    url: policyUrl,
    capability
  })
  return read === null ? null : { policy: read.data, etag: read.etag }
}

/**
 * Reads the access-control policy at `policyUrl`. Returns `null` when no policy
 * is set (or it is not visible to you).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param [options.capability] {IZcap}
 * @returns {Promise<PolicyDocument | null>}
 */
export async function readPolicy(
  context: ClientContext,
  { policyUrl, capability }: { policyUrl: string; capability?: IZcap }
): Promise<PolicyDocument | null> {
  return readData<PolicyDocument>(context, { url: policyUrl, capability })
}

/**
 * Sets (creates or replaces) the access-control policy at `policyUrl`, under
 * an optional precondition. Throws `ValidationError` when both `ifMatch` and
 * `ifNoneMatch` are named.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param options.policy {PolicyDocument}
 * @param [options.ifMatch] {string}   update only if the policy's ETag matches
 * @param [options.ifNoneMatch] {boolean}   write only if no policy is set
 * @param [options.capability] {IZcap}
 * @returns {Promise<{ etag?: string }>}   the policy's new ETag
 */
export async function writePolicy(
  context: ClientContext,
  {
    policyUrl,
    policy,
    ifMatch,
    ifNoneMatch,
    capability
  }: WritePrecondition & {
    policyUrl: string
    policy: PolicyDocument
    capability?: IZcap
  }
): Promise<{ etag?: string }> {
  const response = await send(context, {
    url: policyUrl,
    method: 'PUT',
    capability,
    json: policy,
    headers: writeHeaders({ precondition: { ifMatch, ifNoneMatch } })
  })
  return { etag: readEtag(response) }
}

/**
 * Whether the policy at `policyUrl` is `PublicCanRead` -- the shared body of
 * the `isPublic()` sugar on the three handle classes.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param [options.capability] {IZcap}
 * @returns {Promise<boolean>}
 */
export async function isPublicPolicy(
  context: ClientContext,
  options: { policyUrl: string; capability?: IZcap }
): Promise<boolean> {
  const policy = await readPolicy(context, options)
  return policy?.type === 'PublicCanRead'
}

/**
 * Sets the policy at `policyUrl` to `PublicCanRead` -- the shared body of the
 * `setPublic()` sugar on the three handle classes.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param [options.ifMatch] {string}   update only if the policy's ETag matches
 * @param [options.ifNoneMatch] {boolean}   write only if no policy is set
 * @param [options.capability] {IZcap}
 * @returns {Promise<{ etag?: string }>}   the policy's new ETag
 */
export async function setPublicPolicy(
  context: ClientContext,
  options: WritePrecondition & { policyUrl: string; capability?: IZcap }
): Promise<{ etag?: string }> {
  return writePolicy(context, {
    ...options,
    policy: { type: 'PublicCanRead' }
  })
}

/**
 * Removes the access-control policy at `policyUrl`, reverting to
 * capability-only access. Idempotent: deleting an absent policy succeeds. The
 * server keeps a tombstone in the policy's place.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyUrl {string}   the policy sub-resource URL
 * @param [options.ifMatch] {string}   delete only if the policy's ETag matches
 * @param [options.capability] {IZcap}
 * @returns {Promise<{ etag?: string }>}   the tombstone's ETag; absent when
 *   there was no policy to delete
 */
export async function deletePolicy(
  context: ClientContext,
  {
    policyUrl,
    ifMatch,
    capability
  }: { policyUrl: string; ifMatch?: string; capability?: IZcap }
): Promise<{ etag?: string }> {
  const response = await send(context, {
    url: policyUrl,
    method: 'DELETE',
    capability,
    idempotent: true,
    headers: writeHeaders({ precondition: { ifMatch } })
  })
  return { etag: readEtag(response) }
}
