/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one read-side rule for a served `createdBy`: it is kept only as a
 * non-empty array of DIDs. Every read that hands a server object to a caller
 * typed with `createdBy?: IDID[]` passes it through here, so a caller never
 * holds a string (or any other value) under that type.
 */
import { isCreatedBy } from '@interop/storage-core'

/**
 * Returns the served object with `createdBy` left off when it is anything but
 * a non-empty array of DIDs. An object whose `createdBy` is absent or valid is
 * returned as it is, not copied.
 *
 * @param served {object}
 * @returns {object}
 */
export function withCheckedCreatedBy<Served extends object>(
  served: Served
): Served {
  if (!('createdBy' in served) || isCreatedBy(served.createdBy)) {
    return served
  }
  const { createdBy: _dropped, ...rest } = served
  return rest as Served
}
