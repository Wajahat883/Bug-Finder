import { MongoClient, Db, ObjectId } from "mongodb";
import { logger } from "./logger";

let client: MongoClient | null = null;
let db: Db | null = null;

export async function connectDb(): Promise<Db> {
  if (db) return db;

  const uri = process.env["MONGODB_URI"] || process.env["MONGO_URI"];

  if (!uri) {
    logger.info("No MONGODB_URI set — using in-memory store");
    db = getInMemoryDb();
    return db;
  }

  try {
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
    await client.connect();
    db = client.db();
    logger.info({ uri: uri.replace(/\/\/[^@]+@/, "//***@") }, "MongoDB connected");
    try { await ensureIndexes(db); } catch (ie) { logger.warn({ err: ie }, "Index creation skipped"); }
    return db;
  } catch (err) {
    logger.warn({ err }, "MongoDB connection failed — using in-memory store");
    db = getInMemoryDb();
    return db;
  }
}

export function getDb(): Db {
  if (!db) throw new Error("Database not initialized. Call connectDb() first.");
  return db;
}

export { ObjectId };

// ---------------------------------------------------------------------------
// In-memory fallback database (for environments without MongoDB)
// ---------------------------------------------------------------------------
type Doc = Record<string, unknown> & { _id: ObjectId };
type Collection = {
  docs: Doc[];
  findOne: (query: Record<string, unknown>) => Doc | null;
  find: (query?: Record<string, unknown>) => {
    toArray: () => Doc[];
    sort: (s: Record<string, 1 | -1>) => { toArray: () => Doc[] };
    skip: (n: number) => { toArray: () => Doc[]; sort: (s: Record<string, 1 | -1>) => { toArray: () => Doc[] } };
    limit: (n: number) => { toArray: () => Doc[]; sort: (s: Record<string, 1 | -1>) => { toArray: () => Doc[] }; skip: (n: number) => { toArray: () => Doc[] } };
  };
  insertOne: (doc: Record<string, unknown>) => Promise<{ insertedId: ObjectId }>;
  updateOne: (q: Record<string, unknown>, upd: Record<string, unknown>, opts?: { upsert?: boolean }) => Promise<{ upsertedId?: ObjectId }>;
  updateMany: (q: Record<string, unknown>, upd: Record<string, unknown>) => Promise<void>;
  deleteOne: (q: Record<string, unknown>) => Promise<void>;
  deleteMany: (q: Record<string, unknown>) => Promise<{ deletedCount: number }>;
  countDocuments: (q?: Record<string, unknown>) => Promise<number>;
};

function matchesQuery(doc: Doc, query: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(query)) {
    if (k === "$or" && Array.isArray(v)) {
      if (!(v as Record<string, unknown>[]).some(clause => matchesQuery(doc, clause))) return false;
      continue;
    }
    if (v !== null && typeof v === "object" && !ObjectId.isValid(v as string)) {
      const ops = v as Record<string, unknown>;
      if ("$in" in ops) {
        if (!(ops["$in"] as unknown[]).includes(doc[k])) return false;
      } else if ("$ne" in ops) {
        if (String(doc[k] ?? "") === String(ops["$ne"])) return false;
      } else if ("$regex" in ops) {
        const re = new RegExp(ops["$regex"] as string, (ops["$options"] as string) || "");
        if (!re.test(String(doc[k] ?? ""))) return false;
      } else if ("$gte" in ops || "$lte" in ops) {
        const val = doc[k] as number;
        if ("$gte" in ops && val < (ops["$gte"] as number)) return false;
        if ("$lte" in ops && val > (ops["$lte"] as number)) return false;
      }
    } else {
      const docVal = doc[k];
      const queryVal = v;
      if (ObjectId.isValid(queryVal as string) && docVal instanceof ObjectId) {
        if (!docVal.equals(queryVal as string)) return false;
      } else if (String(docVal) !== String(queryVal)) {
        return false;
      }
    }
  }
  return true;
}

function makeCollection(name: string): Collection {
  const docs: Doc[] = [];
  return {
    docs,
    findOne(query) {
      const results = docs.filter((d) => matchesQuery(d, query));
      return results[0] ?? null;
    },
    find(query = {}) {
      const filtered = docs.filter((d) => matchesQuery(d, query));
      let _skip = 0;
      let _limit = filtered.length;
      let _sort: Record<string, 1 | -1> | null = null;

      const buildPage = (): Doc[] => {
        let arr = [...filtered];
        if (_sort) {
          const [key, dir] = Object.entries(_sort)[0] ?? [];
          if (key) arr.sort((a, b) => {
            const av = a[key], bv = b[key];
            const an = av instanceof Date ? av.getTime() : Number(av ?? 0);
            const bn = bv instanceof Date ? bv.getTime() : Number(bv ?? 0);
            return (an - bn) * dir;
          });
        }
        return arr.slice(_skip, _skip + _limit);
      };

      // Cursor object — all chainable methods always return the same cursor so
      // arbitrary call order (.sort().skip().limit() or .skip().sort().limit()) works.
      const cursor = {
        toArray: () => buildPage(),
        sort(s: Record<string, 1 | -1>) { _sort = s; return cursor; },
        skip(n: number) { _skip = n; return cursor; },
        limit(n: number) { _limit = n; return cursor; },
      };
      return cursor;
    },
    async insertOne(doc) {
      const id = new ObjectId();
      const full = { ...doc, _id: id } as Doc;
      docs.push(full);
      return { insertedId: id };
    },
    async updateOne(query, update, opts?) {
      let doc = docs.find((d) => matchesQuery(d, query));
      if (!doc && opts?.upsert) {
        const setOnInsert = (update["$setOnInsert"] ?? {}) as Record<string, unknown>;
        const set = (update["$set"] ?? {}) as Record<string, unknown>;
        const id = new ObjectId();
        const newDoc: Doc = { _id: id, ...setOnInsert, ...set };
        docs.push(newDoc);
        return { upsertedId: id };
      }
      if (!doc) return {};
      const set = (update["$set"] ?? {}) as Record<string, unknown>;
      Object.assign(doc, set);
      return {};
    },
    async updateMany(query, update) {
      const matches = docs.filter((d) => matchesQuery(d, query));
      const set = (update["$set"] ?? {}) as Record<string, unknown>;
      for (const doc of matches) Object.assign(doc, set);
    },
    async deleteOne(query) {
      const idx = docs.findIndex((d) => matchesQuery(d, query));
      if (idx !== -1) docs.splice(idx, 1);
    },
    async deleteMany(query) {
      const before = docs.length;
      const toKeep = docs.filter((d) => !matchesQuery(d, query));
      docs.length = 0;
      docs.push(...toKeep);
      return { deletedCount: before - docs.length };
    },
    async countDocuments(query = {}) {
      return docs.filter((d) => matchesQuery(d, query)).length;
    },
  };
}

const memStoreCollections: Record<string, Collection> = {};

function getInMemoryDb(): Db {
  return {
    collection(name: string) {
      if (!memStoreCollections[name]) {
        memStoreCollections[name] = makeCollection(name);
      }
      return memStoreCollections[name] as unknown as ReturnType<Db["collection"]>;
    },
  } as unknown as Db;
}

export function col(name: string) {
  const database = db ?? getInMemoryDb();
  return database.collection(name);
}

async function ensureIndexes(database: Db): Promise<void> {
  try {
    await database.collection("findings").createIndex({ scan_job_id: 1 });
    await database.collection("findings").createIndex({ severity: 1, created_at: -1 });
    await database.collection("findings").createIndex({ target_url: 1 });
    await database.collection("findings").createIndex({ category: 1 });
    // Deduplication key index — enables O(1) lookup before each insert
    await database.collection("findings").createIndex({ dedup_key: 1, target_url: 1 });
    await database.collection("findings").createIndex({ validation_status: 1 });
    await database.collection("findings").createIndex({ last_seen_at: -1 });
    await database.collection("findings").createIndex({ user_id: 1, created_at: -1 });
    await database.collection("scan_jobs").createIndex({ status: 1, created_at: -1 });
    await database.collection("scan_jobs").createIndex({ target_url: 1 });
    await database.collection("targets").createIndex({ domain: 1 }, { unique: true, sparse: true });
    await database.collection("activity_events").createIndex({ timestamp: -1 });
    await database.collection("remediations").createIndex({ created_at: -1 });
    await database.collection("audit_log").createIndex({ created_at: -1 });
    // Data retention: audit logs auto-expire after DATA_RETENTION_DAYS (default 365)
    const retentionDays = parseInt(process.env["DATA_RETENTION_DAYS"] ?? "365");
    await database.collection("audit_log").createIndex(
      { created_at: 1 },
      { expireAfterSeconds: retentionDays * 86400, name: "audit_log_ttl" }
    );
    await database.collection("users").createIndex({ email: 1 }, { unique: true, sparse: true });
    // raw_evidence: TTL index auto-deletes documents after expires_at
    await database.collection("raw_evidence").createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
    await database.collection("raw_evidence").createIndex({ finding_id: 1 }, { unique: true });
    await database.collection("raw_evidence").createIndex({ scan_job_id: 1 });
    await database.collection("scan_credentials").createIndex({ target_id: 1 });
    await database.collection("scan_credentials").createIndex({ target_id: 1, type: 1, label: 1 });
    // Suppression rules: fast lookup by target+dedup_key during saveFinding()
    await database.collection("suppression_rules").createIndex({ target_url: 1, dedup_key: 1 });
    await database.collection("suppression_rules").createIndex({ created_by: 1, created_at: -1 });
    // OIDC PKCE state: TTL index auto-deletes stale states after expires_at
    await database.collection("oidc_pkce_state").createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
    // Baseline scan lookup
    await database.collection("scan_jobs").createIndex({ is_baseline: 1 });
    logger.info("Database indexes ensured");
  } catch (err) {
    logger.warn({ err }, "Index creation failed — continuing without indexes");
  }
}
