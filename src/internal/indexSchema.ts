/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The persisted index schema of a searchable collection: where it is stored,
 * how an attribute is normalized into a stable key, and the guard that refuses
 * a query naming an attribute nobody declared.
 *
 * The schema lives under `indexSchema` inside the collection's `/meta`
 * `custom` object -- which on an encrypted collection is an opaque envelope, so
 * the attribute names (a description of the data model) are never
 * server-visible. Any recipient that can decrypt the collection can therefore
 * discover what is searchable, which is what an app granted access to an
 * existing collection needs: index declarations that lived only in one app's
 * memory would leave every other reader unable to learn them.
 */
import type { IndexDeclaration, IndexSchema } from '../codec.js'
import { ValidationError } from '../errors.js'
import type { ResourceMetadataCustomInput } from '../types.js'

/**
 * The property the schema is stored under inside the collection's metadata
 * `custom` object, alongside the user's own `name` / `tags`.
 */
export const INDEX_SCHEMA_PROPERTY = 'indexSchema'

/**
 * The schema of a collection that has declared nothing yet. Minted fresh on
 * every call rather than shared: a codec installs the schema it is handed by
 * reference, so one shared empty array mutated through any handle would reach
 * every undeclared collection in the process.
 *
 * @returns {IndexSchema}
 */
export function emptyIndexSchema(): IndexSchema {
  return { revision: 0, indexes: [] }
}

/**
 * A deep copy of a schema: new entry objects, and a compound entry's
 * `attribute` array copied too. A codec installs the copy rather than the
 * object it was handed, and the handle layer hands out copies, so no caller
 * holds a reference into the schema a codec blinds and queries by.
 *
 * @param schema {IndexSchema}
 * @returns {IndexSchema}
 */
export function cloneIndexSchema(schema: IndexSchema): IndexSchema {
  return {
    revision: schema.revision,
    indexes: schema.indexes.map(entry => ({
      ...entry,
      attribute: Array.isArray(entry.attribute)
        ? [...entry.attribute]
        : entry.attribute
    }))
  }
}

/**
 * The metadata `custom` object as the index code sees it: the user's own
 * properties plus the schema this module owns.
 */
export type CustomWithIndexSchema = Record<string, unknown> & {
  indexSchema?: IndexSchema
}

/**
 * Normalizes an attribute declaration: a one-element array declares the same
 * simple index as the bare string (the same collapse the underlying index
 * helper applies), so the two forms cannot produce two schema entries.
 *
 * @param attribute {string | string[]}
 * @returns {string | string[]}
 */
export function normalizeAttribute(
  attribute: string | string[]
): string | string[] {
  if (Array.isArray(attribute) && attribute.length === 1) {
    return attribute[0]!
  }
  return attribute
}

/**
 * The stable identity of an attribute declaration, for comparing a new
 * declaration against the persisted ones. Compound attributes join on `|` after
 * percent-encoding each part, so a name containing the separator cannot forge a
 * collision.
 *
 * @param attribute {string | string[]}
 * @returns {string}
 */
export function attributeKey(attribute: string | string[]): string {
  const parts = Array.isArray(attribute) ? attribute : [attribute]
  return parts.map(part => encodeURIComponent(part)).join('|')
}

/**
 * An index declaration as a caller requests it, before it is stamped with the
 * schema revision that adds it.
 */
type IndexRequest = { attribute: string | string[]; unique?: boolean }

/**
 * How an error message names a declaration's uniqueness.
 *
 * @param unique {boolean | undefined}
 * @returns {string}
 */
function uniquenessLabel(unique: boolean | undefined): string {
  return unique === true ? 'unique' : 'non-unique'
}

/**
 * Normalizes a batch of requested declarations, keyed by
 * {@link attributeKey}. A key repeated on the same terms collapses to one
 * entry. A key repeated with different uniqueness throws `ValidationError`.
 *
 * @param indexes {IndexRequest[]}
 * @returns {Map<string, IndexRequest>}
 */
export function normalizeIndexRequests(
  indexes: IndexRequest[]
): Map<string, IndexRequest> {
  const requested = new Map<string, IndexRequest>()
  for (const { attribute, unique } of indexes) {
    const declared = normalizeAttribute(attribute)
    const key = attributeKey(declared)
    const seen = requested.get(key)
    if (seen === undefined) {
      requested.set(key, { attribute: declared, unique })
    } else if ((seen.unique === true) !== (unique === true)) {
      throw new ValidationError(
        `Cannot declare index "${key}" as both ` +
          `${uniquenessLabel(unique)} and ${uniquenessLabel(seen.unique)} ` +
          'in the same declareIndexes() call.'
      )
    }
  }
  return requested
}

/**
 * Adds the requested declarations to a schema. An attribute already declared
 * on the same terms is skipped, and one declared with different uniqueness
 * throws `ValidationError`. Every added entry shares one `revision` bump.
 *
 * @param options {object}
 * @param options.schema {IndexSchema}   the persisted schema
 * @param options.requested {Map<string, IndexRequest>}   from
 *   {@link normalizeIndexRequests}
 * @returns {IndexSchema | null}   the next schema, or `null` when every
 *   requested attribute is already declared
 */
export function mergeIndexDeclarations({
  schema,
  requested
}: {
  schema: IndexSchema
  requested: Map<string, IndexRequest>
}): IndexSchema | null {
  const existingByKey = new Map(
    schema.indexes.map(entry => [attributeKey(entry.attribute), entry])
  )
  const revision = schema.revision + 1
  const added: IndexDeclaration[] = []
  for (const [key, { attribute, unique }] of requested) {
    const existing = existingByKey.get(key)
    if (existing === undefined) {
      added.push({
        attribute,
        ...(unique === true && { unique: true as const }),
        addedIn: revision
      })
    } else if ((existing.unique === true) !== (unique === true)) {
      throw new ValidationError(
        `Cannot declare index "${key}" as ${uniquenessLabel(unique)}: this ` +
          'collection already declares it as ' +
          `${uniquenessLabel(existing.unique)}. An index cannot change ` +
          'uniqueness in place -- already-stored documents were indexed under ' +
          'the old terms.'
      )
    }
  }
  if (added.length === 0) {
    return null
  }
  return { revision, indexes: [...schema.indexes, ...added] }
}

/**
 * Reads the persisted schema out of a decoded metadata `custom` object,
 * returning {@link emptyIndexSchema} when none is stored (or when what is
 * stored is malformed -- a foreign writer's value must not crash a read path,
 * and treating it as "nothing declared" makes the next `declareIndex` rewrite
 * it).
 *
 * @param custom {unknown}   the decoded `custom` object from `/meta`
 * @returns {IndexSchema}
 */
export function readIndexSchema(custom: unknown): IndexSchema {
  const stored = (custom as CustomWithIndexSchema | undefined | null)?.[
    INDEX_SCHEMA_PROPERTY
  ]
  if (stored === null || typeof stored !== 'object') {
    return emptyIndexSchema()
  }
  const { revision, indexes } = stored as Partial<IndexSchema>
  if (typeof revision !== 'number' || !Array.isArray(indexes)) {
    return emptyIndexSchema()
  }
  const valid = indexes.filter(
    entry =>
      entry !== null &&
      typeof entry === 'object' &&
      (typeof entry.attribute === 'string' || Array.isArray(entry.attribute))
  )
  return { revision, indexes: valid }
}

/**
 * Every attribute name a schema makes searchable: each simple index's name and,
 * for a compound index, each of its member names (a compound index is queryable
 * by a leading prefix of its members, so any member can legitimately appear in
 * a query).
 *
 * @param schema {IndexSchema}
 * @returns {Set<string>}
 */
function declaredAttributeNames(schema: IndexSchema): Set<string> {
  const names = new Set<string>()
  for (const entry of schema.indexes) {
    const parts = Array.isArray(entry.attribute)
      ? entry.attribute
      : [entry.attribute]
    for (const part of parts) {
      names.add(part)
    }
  }
  return names
}

/**
 * Refuses a search over an attribute the persisted schema does not declare.
 *
 * This guard is load-bearing rather than cosmetic: the underlying index helper
 * builds a query only from the attributes it has been told about, so an
 * undeclared attribute silently yields a term-less query -- which matches
 * nothing (or, worse, everything the other terms allow) instead of reporting
 * the mistake. Naming the attribute makes the "this app never declared it, and
 * neither did any other writer" case obvious.
 *
 * @param options {object}
 * @param options.schema {IndexSchema}   the collection's persisted schema
 * @param [options.equals] {object | object[]}   the query's equality terms
 * @param [options.has] {string | string[]}   the query's presence terms
 * @returns {void}
 */
export function assertQueryAttributes({
  schema,
  equals,
  has
}: {
  schema: IndexSchema
  equals?: Record<string, unknown> | Array<Record<string, unknown>>
  has?: string | string[]
}): void {
  const declared = declaredAttributeNames(schema)
  const queried: string[] = []
  if (equals !== undefined) {
    for (const term of Array.isArray(equals) ? equals : [equals]) {
      queried.push(...Object.keys(term))
    }
  }
  if (has !== undefined) {
    queried.push(...(Array.isArray(has) ? has : [has]))
  }
  for (const attribute of queried) {
    if (!declared.has(attribute)) {
      throw new ValidationError(
        `Cannot search on attribute "${attribute}": this collection's index ` +
          'schema does not declare it, so no stored document carries a token ' +
          'for it and the query would silently match nothing. Declare it with ' +
          'declareIndex({ attribute }) -- note that documents written before ' +
          'the declaration are not indexed until they are rewritten.'
      )
    }
  }
}

/**
 * The `custom` a full-replacement Collection annotation write sends: the
 * caller's `custom`, plus the stored schema when the caller's names none of
 * its own. The schema is collection state this module owns rather than an
 * annotation the caller is replacing, so a write about `name` / `tags` must
 * not clear it on the way through. A `custom` that names the `indexSchema`
 * member (a `declareIndex` write, the read-merge-write sugar, or a caller
 * clearing the schema with `indexSchema: undefined`) is returned as given.
 *
 * The stored `custom` is opened only when there is something to carry, which
 * is what the `stored` thunk is for: on an encrypted collection the open is a
 * decrypt, and the caller usually holds the opened value from the `meta()`
 * read the write composes against. An opened value that is not an object (a
 * stored `custom` this client cannot open, or a foreign writer's scalar)
 * carries nothing: the write goes out as given, which keeps `setMeta` the way
 * to replace such a value. The same policy the configuration write applies
 * when it cannot re-seal the stored `custom`.
 *
 * @param options {object}
 * @param options.custom {ResourceMetadataCustomInput}   the write's `custom`
 * @param options.stored {function}   resolves the stored `custom` opened
 *   through the codec, or `undefined` when there is none or it cannot be
 *   opened here
 * @returns {Promise<ResourceMetadataCustomInput>}
 */
export async function withStoredIndexSchema({
  custom,
  stored
}: {
  custom: ResourceMetadataCustomInput
  stored: () => Promise<unknown>
}): Promise<ResourceMetadataCustomInput> {
  if (INDEX_SCHEMA_PROPERTY in custom) {
    return custom
  }
  const opened = await stored()
  if (
    opened === null ||
    typeof opened !== 'object' ||
    !(INDEX_SCHEMA_PROPERTY in opened)
  ) {
    return custom
  }
  return {
    ...custom,
    [INDEX_SCHEMA_PROPERTY]: (opened as CustomWithIndexSchema)[
      INDEX_SCHEMA_PROPERTY
    ]
  }
}
