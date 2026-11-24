/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A `PathHandler` service entry for a `did:webvh` document minted by a test:
 * the service that maps a DID URL path to an https URL.
 */
import { PATH_HANDLER_SERVICE_TYPE } from '@interop/did-method-webvh'
import type { ServiceEndpoint } from '@interop/did-method-webvh'

/**
 * A `PathHandler` service mounting `path` at `serviceEndpoint`.
 *
 * @param options {object}
 * @param options.path {string}
 * @param options.serviceEndpoint {string}
 * @returns {ServiceEndpoint}
 */
export function pathHandler({
  path,
  serviceEndpoint
}: {
  path: string
  serviceEndpoint: string
}): ServiceEndpoint {
  const id = path === '/' ? '#root' : `#${path.slice(1).replace(/\//g, '-')}`
  return { id, type: PATH_HANDLER_SERVICE_TYPE, path, serviceEndpoint }
}
