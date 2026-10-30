/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `mapError`: the translation of a thrown ky/ezcap error into the `PwsError`
 * subclass that represents it. It dispatches on the full problem-type URI in
 * the server's `application/problem+json` body (the shared `ProblemTypes`
 * registry from `@interop/storage-core`), then on the HTTP status, and strips
 * control characters from and length-caps every server string it carries
 * through. Kept apart from `errors.ts` so the class hierarchy loads with no
 * runtime dependency: the registry is the one runtime value the error path
 * reads from `@interop/storage-core`.
 */
import { ProblemTypes, type Problem } from '@interop/storage-core'

import {
  AlreadyRevokedError,
  AuthRequiredError,
  CapabilityExpiredError,
  CapabilityRevokedError,
  cleanText,
  ConflictError,
  httpStatus,
  MAX_TEXT_LENGTH,
  NotFoundError,
  NotImplementedError,
  PayloadTooLargeError,
  PreconditionFailedError,
  QuotaExceededError,
  ValidationError,
  PwsError,
  PwsServerError,
  type PwsErrorOptions
} from '../errors.js'

/**
 * The shape of a thrown ky/ezcap error after `@interop/http-client` has
 * augmented it.
 */
interface HttpClientError {
  status?: number
  requestUrl?: string
  message?: string
  response?: { status?: number }
  // Unvalidated server JSON: `type` and `title` may be any JSON value.
  data?: {
    type?: unknown
    title?: unknown
    errors?: Array<{ detail?: string }>
  }
}

/**
 * A `PwsError` subclass constructor (the base and every subclass share this
 * `(message, options)` signature).
 */
type PwsErrorClass = new (
  message: string,
  options?: PwsErrorOptions
) => PwsError

// Client-side hygiene limit on a server-supplied problem-type URI.
const MAX_TYPE_LENGTH = 2048

/**
 * Extracts the fragment of a problem-type URI (the part after `#`, e.g.
 * `quota-exceeded` from `https://w3id.org/pws#quota-exceeded`). Used only to
 * make a fallback message readable, never for dispatch.
 *
 * @param problemType {string}   a problem-type URI
 * @returns {string}
 */
function problemFragment(problemType: string): string {
  return problemType.split('#')[1] ?? ''
}

/**
 * Maps each problem-type URI to the `PwsError` subclass that represents it.
 * Keyed by the full URIs of the shared `ProblemTypes` registry from
 * `@interop/storage-core`, so the kinds stay in lockstep with the server and a
 * foreign namespace that reuses a fragment does not match. A `Map` (rather than
 * a plain object) means a `type` such as `x#constructor` cannot resolve to an
 * inherited property.
 */
const ERROR_CLASS_BY_TYPE = new Map<string, PwsErrorClass>([
  [ProblemTypes.NOT_FOUND, NotFoundError],
  [ProblemTypes.CAPABILITY_REVOKED, CapabilityRevokedError],
  [ProblemTypes.CAPABILITY_EXPIRED, CapabilityExpiredError],
  [ProblemTypes.INVALID_ID, ValidationError],
  [ProblemTypes.INVALID_REQUEST_BODY, ValidationError],
  [ProblemTypes.INVALID_CURSOR, ValidationError],
  [ProblemTypes.MISSING_CONTENT_TYPE, ValidationError],
  [ProblemTypes.INVALID_AUTHORIZATION_HEADER, ValidationError],
  [ProblemTypes.CONTROLLER_MISMATCH, ValidationError],
  [ProblemTypes.INVALID_IMPORT, ValidationError],
  [ProblemTypes.UNSUPPORTED_ENCRYPTION_SCHEME, ValidationError],
  [ProblemTypes.ENCRYPTION_SCHEME_MISMATCH, ValidationError],
  [ProblemTypes.CAPABILITY_ALREADY_REVOKED, AlreadyRevokedError],
  [ProblemTypes.MISSING_AUTHORIZATION, AuthRequiredError],
  [ProblemTypes.RESERVED_ID, ConflictError],
  [ProblemTypes.ID_CONFLICT, ConflictError],
  [ProblemTypes.UNSUPPORTED_BACKEND, ConflictError],
  [ProblemTypes.REPLICA_REFUSED, ConflictError],
  [ProblemTypes.BACKEND_IMMUTABLE, ConflictError],
  [ProblemTypes.ENCRYPTION_IMMUTABLE, ConflictError],
  [ProblemTypes.ENCRYPTION_HISTORY_LOG_GOVERNED, ConflictError],
  [ProblemTypes.REVISIONS_IMMUTABLE, ConflictError],
  [ProblemTypes.RESOURCE_IMMUTABLE, ConflictError],
  [ProblemTypes.PRECONDITION_FAILED, PreconditionFailedError],
  [ProblemTypes.PAYLOAD_TOO_LARGE, PayloadTooLargeError],
  [ProblemTypes.QUOTA_EXCEEDED, QuotaExceededError],
  [ProblemTypes.UNSUPPORTED_OPERATION, NotImplementedError],
  [ProblemTypes.STORAGE_ERROR, PwsServerError],
  [ProblemTypes.INTERNAL_ERROR, PwsServerError]
])

/**
 * Translates a thrown ky/ezcap error into the appropriate `PwsError` subclass,
 * carrying through the server's `problem+json` fields. Dispatches on the
 * full problem-type URI in `type` when it is a known `ProblemTypes` entry,
 * falling back to the HTTP status otherwise. Server strings (`type`, `title`,
 * each problem's `detail` and `pointer`) are stripped of control characters
 * and length-capped; a non-string `type` or `title` is dropped.
 *
 * @param err {unknown}   the caught error
 * @returns {PwsError}
 */
export function mapError(err: unknown): PwsError {
  if (err instanceof PwsError) {
    return err
  }

  const httpError = (err ?? {}) as HttpClientError
  const status = httpStatus(httpError)
  const data = httpError.data
  const type = cleanText(data?.type, MAX_TYPE_LENGTH)
  const title = cleanText(data?.title, MAX_TEXT_LENGTH)
  // Guard with `Array.isArray`, not just optional chaining: a non-conformant
  // `problem+json` body with `errors` as a non-array (e.g. `"boom"`) is truthy,
  // so `?.map` would throw a `TypeError` and mask the real `PwsError`. Each
  // entry is likewise unvalidated server JSON (may be `null` or a primitive),
  // so read it defensively; an entry without a string `detail` is dropped, and
  // a non-string `pointer` is dropped from its entry.
  const problems = Array.isArray(data?.errors)
    ? data.errors.flatMap((entry): Problem[] => {
        if (entry === null || typeof entry !== 'object') {
          return []
        }
        const { detail, pointer } = entry as {
          detail?: unknown
          pointer?: unknown
        }
        const cleanDetail = cleanText(detail, MAX_TEXT_LENGTH)
        if (cleanDetail === undefined) {
          return []
        }
        const cleanPointer = cleanText(pointer, MAX_TEXT_LENGTH)
        return [
          {
            detail: cleanDetail,
            ...(cleanPointer !== undefined && { pointer: cleanPointer })
          }
        ]
      })
    : undefined
  const details = problems?.map(problem => problem.detail)
  const requestUrl = httpError.requestUrl
  const fragment = type === undefined ? '' : problemFragment(type)
  const baseMessage =
    typeof httpError.message === 'string'
      ? httpError.message
      : 'PWS request failed'
  // Without a server title, name the problem kind for readability.
  const message =
    title ?? (fragment === '' ? baseMessage : `${baseMessage} (${fragment})`)
  const options = {
    status,
    type,
    title,
    problems,
    details,
    requestUrl,
    cause: err
  }

  // Dispatch on the full problem-type URI when the server sent a known one,
  // falling through to the status-based switch otherwise.
  const ErrorClass =
    type === undefined ? undefined : ERROR_CLASS_BY_TYPE.get(type)
  if (ErrorClass) {
    return new ErrorClass(message, options)
  }

  switch (status) {
    case 400:
      return new ValidationError(message, options)
    case 401:
    case 403:
      return new AuthRequiredError(message, options)
    case 404:
      return new NotFoundError(message, options)
    case 415:
    case 422:
      return new ValidationError(message, options)
    case 409:
      return new ConflictError(message, options)
    case 412:
      return new PreconditionFailedError(message, options)
    case 413:
      return new PayloadTooLargeError(message, options)
    case 501:
      return new NotImplementedError(message, options)
    case 507:
      return new QuotaExceededError(message, options)
  }

  if (typeof status === 'number' && status >= 500) {
    return new PwsServerError(message, options)
  }

  return new PwsError(message, options)
}
