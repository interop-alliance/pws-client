/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Vitest global setup for the live-server integration tier. When
 * `TEST_SERVER_URL` is unset it boots the reference server in-process on an
 * OS-assigned port over a temporary filesystem backend, publishes its base
 * server URL (the `baseServerUrl` a `PwsClient` takes) through
 * `TEST_SERVER_URL` for the suites, and tears the server down (which removes
 * the temp dir) after the run. When `TEST_SERVER_URL` is already set, it
 * leaves it alone, so the tier can still be pointed at an external server;
 * set it to that server's base server URL.
 */
import {
  openTempBackend,
  startTestServer
} from '@interop/web-spaces-server/testing'

export default async function setup(): Promise<() => Promise<void>> {
  if (process.env.TEST_SERVER_URL) {
    return async () => {}
  }
  const backend = await openTempBackend()
  const { fastify, baseServerUrl } = await startTestServer({ backend })
  process.env.TEST_SERVER_URL = baseServerUrl
  return async () => {
    await fastify.close()
  }
}
