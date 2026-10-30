/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/paths/layout` subpath entry: the part of the
 * `./paths` grammar that needs nothing beyond the platform `URL`. It holds
 * the spec's Server Layout above a Space (`serviceDescriptionUrl`,
 * `spacesRepositoryUrl` and `spaceUrlById`, each from a base server URL, with
 * `baseServerUrlOf` as their inverse), the one rule for a base server URL
 * (`canonicalBaseServerUrl`) and for a Space URL (`canonicalSpaceUrl`), the
 * id read off a Space URL (`spaceIdOfUrl`), and `splitCollectionUrl`.
 *
 * `./paths` re-exports every one of these, so a consumer that already imports
 * that entry has nothing to change. This entry exists for the consumer that
 * validates one URL and wants no package behind it: an onboarding query
 * naming a base server URL, a record envelope naming a Space. `./paths`
 * carries the Reserved Path Segment Registry from `@interop/storage-core`
 * for its id guards and the root capability grammar from `@interop/zcap`,
 * which a bundler shakes away but plain Node ESM evaluates on first import.
 * The static closure of this entry holds no external package at all, and
 * `test/node/import-graph.test.ts` enforces it.
 *
 * Every export is a pure function with no I/O and no client state; each
 * throws `ValidationError` on a URL it refuses.
 */
export {
  canonicalBaseServerUrl,
  serviceDescriptionUrl,
  spacesRepositoryUrl,
  spaceUrlById,
  baseServerUrlOf,
  splitCollectionUrl,
  canonicalSpaceUrl,
  spaceIdOfUrl
} from '../internal/layout.js'
