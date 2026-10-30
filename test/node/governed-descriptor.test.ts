/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `isGovernedDescriptor`, the one predicate that tells a
 * server-derived log-governed projection from a client-written descriptor.
 * The member comes off the wire, so the check is structural: an absent
 * `history` answers false, and a present but malformed one is refused with
 * `ValidationError` rather than vouched for or passed off as client-written.
 */
import { describe, it, expect } from 'vitest'

import { isGovernedDescriptor } from '../../src/internal/describe.js'
import { ValidationError } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'

/**
 * A descriptor whose `history` member is whatever the test supplies, typed
 * as the wire type so the malformed shapes can be passed in.
 *
 * @param history {unknown}
 * @returns {CollectionEncryption}
 */
function withHistory(history: unknown): CollectionEncryption {
  return { scheme: 'edv', history } as unknown as CollectionEncryption
}

describe('isGovernedDescriptor', () => {
  it('answers true for a well-formed history pointer', () => {
    expect(
      isGovernedDescriptor(
        withHistory({
          method: 'resource-log:1.0',
          resource: 'https://was.example/space/s/c/meta/log'
        })
      )
    ).toBe(true)
  })

  it('answers false for a descriptor without history', () => {
    expect(isGovernedDescriptor({ scheme: 'edv' })).toBe(false)
  })

  it.each([
    ['null', null],
    ['a string', 'https://was.example/space/s/c/meta/log'],
    ['an array', ['resource-log:1.0']],
    ['an object missing resource', { method: 'resource-log:1.0' }],
    ['an object missing method', { resource: 'https://was.example/log' }],
    ['non-string members', { method: 1, resource: 2 }]
  ])('refuses a history of %s with ValidationError', (_label, history) => {
    expect(() => isGovernedDescriptor(withHistory(history))).toThrow(
      ValidationError
    )
    expect(() => isGovernedDescriptor(withHistory(history))).toThrow(
      /malformed `history` member/
    )
  })
})
