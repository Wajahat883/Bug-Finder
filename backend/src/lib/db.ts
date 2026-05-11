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
  find: (query?: Record<string, unknown>) => { toArray: () => Doc[]; sort: (s: unknown) => { toArray: () => Doc[] } };
  insertOne: (doc: Record<string, unknown>) => Promise<{ insertedId: ObjectId }>;
  updateOne: (q: Record<string, unknown>, upd: Record<string, unknown>) => Promise<void>;
  deleteOne: (q: Record<string, unknown>) => Promise<void>;
  countDocuments: (q?: Record<string, unknown>) => Promise<number>;
};

function matchesQuery(doc: Doc, query: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(query)) {
    if (v !== null && typeof v === "object" && !ObjectId.isValid(v as string)) {
      const ops = v as Record<string, unknown>;
      if ("$in" in ops) {
        if (!(ops["$in"] as unknown[]).includes(doc[k])) return false;
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
      if ("_id" in query) {
        const id = query["_id"];
        return docs.find((d) => d._id.equals(id as string)) ?? null;
      }
      return docs.find((d) => matchesQuery(d, query)) ?? null;
    },
    find(query = {}) {
      const filtered = docs.filter((d) => matchesQuery(d, query));
      const self = {
        toArray: () => filtered,
        sort: (_s: unknown) => ({ toArray: () => filtered }),
      };
      return self;
    },
    async insertOne(doc) {
      const id = new ObjectId();
      const full = { ...doc, _id: id } as Doc;
      docs.push(full);
      return { insertedId: id };
    },
    async updateOne(query, update) {
      const doc = docs.find((d) => matchesQuery(d, query));
      if (!doc) return;
      const set = (update["$set"] ?? {}) as Record<string, unknown>;
      Object.assign(doc, set);
    },
    async deleteOne(query) {
      const idx = docs.findIndex((d) => matchesQuery(d, query));
      if (idx !== -1) docs.splice(idx, 1);
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
