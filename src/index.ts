/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Public entry point for `@interop/pws-client`: the `PwsClient` and its
 * navigational handles, the typed error hierarchy, and the shared types.
 */
export { PwsClient } from './PwsClient.js'
export { Space } from './Space.js'
export { Collection } from './Collection.js'
export { Resource } from './Resource.js'
export { zcapClientForSigner } from './zcapClient.js'
export { discoverService, readServiceDescription } from './internal/service.js'

export { parseSpaceTarget } from './internal/paths.js'
export { allowsAction } from './internal/grant.js'
export type { ParsedSpacePath } from './internal/paths.js'
export { readEtag, writeHeaders } from './internal/conditional.js'
export { isGovernedDescriptor } from './internal/describe.js'
// The `changes` feed guards a consumer filters `Collection.changes()` pages
// with, the List Collections tombstone guard, and the problem-type registry a
// consumer tells one `ConflictError` kind from another by, so a consumer needs
// no direct `@interop/storage-core` dependency.
export {
  isCollectionTombstoneSummary,
  isJsonResourceChange,
  isResourceChange,
  ProblemTypes
} from '@interop/storage-core'
export type { WritePrecondition } from './internal/conditional.js'

export {
  PwsError,
  NotFoundError,
  CapabilityRevokedError,
  CapabilityExpiredError,
  ValidationError,
  AlreadyRevokedError,
  AuthRequiredError,
  NotImplementedError,
  NotSupportedError,
  IncompatibleServerError,
  ConflictError,
  PreconditionFailedError,
  PayloadTooLargeError,
  QuotaExceededError,
  EncryptionError,
  EncryptOnlyCipherError,
  UnverifiedDescriptorError,
  KeyUnwrapError,
  IntegrityError,
  UnknownEpochError,
  PwsSyncAuthError,
  PwsSyncCheckpointError,
  PwsSyncConflictError,
  PwsSyncNotFoundError,
  PwsServerError,
  httpStatus,
  isDenialError
} from './errors.js'
export { mapError } from './internal/mapError.js'

export { isChunkedWrite } from './codec.js'
export type {
  DecodedStream,
  ResourceCodec,
  EncryptionProvider,
  ChunkedWrite,
  CodecRequestContext,
  CodecWrite,
  MetaReadSlot,
  MetaWriteSlot,
  EncodedWrite,
  ResponseLike,
  BlindedQuery,
  CodecIndexing,
  IndexDeclaration,
  IndexSchema
} from './codec.js'

export type {
  Json,
  JsonPrimitive,
  JsonObject,
  JsonArray,
  ResourceData,
  Action,
  ActionInput,
  ChangeDocument,
  ChangesCheckpoint,
  ChangesPage,
  ContainerChangeDocument,
  PolicyChangeDocument,
  ResourceChangeDocument,
  SpaceMetadata,
  CollectionWritableFields,
  CollectionEncryption,
  CollectionEncryptionEpoch,
  CollectionEncryptionRecipient,
  CollectionEncryptionHmac,
  EncryptionWithHmac,
  CollectionSummary,
  CollectionTombstoneSummary,
  CollectionsList,
  SpaceSummary,
  SpaceListing,
  ResourceSummary,
  CollectionResourcesList,
  ResourceMetadata,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput,
  CollectionMetadata,
  CollectionGenerator,
  AddResult,
  FindPage,
  ImportStats,
  PolicyDocument,
  PolicyTombstone,
  LinkSet,
  LinkSetEntry,
  HandleOptions,
  EncryptionOverride,
  BackendReference,
  BackendDescriptor,
  BackendRegistration,
  BackendConnectionInput,
  BackendConnectionPublic,
  StorageLimit,
  CollectionUsage,
  BackendUsage,
  SpaceQuotaReport,
  ReplicaRegistration,
  ReplicaSummary,
  ReplicaRole,
  ReplicaListing,
  ReplicaStatus,
  ReplicaCollectionStatus,
  ReplicaStallReason,
  WriteStamp,
  ServiceDescription,
  ServiceDescriptionVersionEntry,
  PwsVersionEntry,
  ServiceInfo,
  GrantOptions,
  RequestInput,
  IZcap,
  IDelegatedZcap,
  IRootZcap,
  IDID,
  ISigner
} from './types.js'

/**
 * The Collection Metadata `custom` object as the blinded-index code sees it --
 * the user's own properties plus the `indexSchema` `declareIndex` persists.
 * The annotation for a caller reading the schema off a `describe()` result.
 */
export type { CustomWithIndexSchema } from './internal/indexSchema.js'
