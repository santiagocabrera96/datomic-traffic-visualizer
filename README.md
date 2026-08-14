# learn-datomic-caching

Goal: understand exactly what Datomic's transactor and peer say to their
storage backend and to memcached, by capturing the raw TCP traffic and
turning it into a readable sequence diagram (`events.svg`).

Local stack: a Datomic transactor, backed by **DynamoDB Local** (not real
AWS) for storage, plus a local **memcached** for the peer's read cache, plus
this JVM acting as the peer. Everything runs on `127.0.0.1`, on different
ports (8000 = DynamoDB Local, 11211 = memcached).

Historical note: the project *started* with Postgres as the storage backend,
with an earlier generation of inspection code (`pgsql_inspect.clj`,
`load_data.clj`, `inspect_traffic*.clj`, a `prompt.md` describing that setup)
before pivoting to DynamoDB Local. Those files have been removed — current
behavior lives entirely in `dynamo_inspect.clj` + `memcache_inspect.clj` +
`traffic_diagram.clj` + `process.clj`, described below.

## Running it end to end

1. `scripts/setup.sh` — one-time install of memcached, Datomic Pro,
   DynamoDB Local, tshark.
2. Capture traffic *before* loading `setup.clj` (tshark needs to be running
   first to see the TCP handshakes):
   ```
   scripts/capture.sh [path]
   ```
   (writes to `path` if given, else `$TSHARK_LOG`, else `/tmp/tshark.log`.
   Using a non-default path? Either export `TSHARK_LOG` before the next step,
   or `(reset! setup/tshark-log "that/path")` once you're at the REPL, so the
   port mapping and `process.clj`'s read line up with it.)
3. `clj -M:setup` (or load `src/setup.clj` in your editor's REPL) — there's
   no `-main` and no way to start just one of dynamodb/memcached/transactor;
   loading the namespace starts all three (only makes sense together, since
   `pids`/the port mapping built from them needs all three to exist),
   connects a peer, and transacts the schema, all as top-level side effects.
   `start-port-watcher!` (started automatically) keeps `port-owners` current
   throughout; its `add-watch` dumps it to `(ports-path)` on every change, so
   it's already on disk whenever you're ready to tear the stack down.
   `since` is captured right before startup, for step 5's `:since`.
4. Do your peer work at the REPL (`d/transact`, `d/pull`, ...) — see the
   examples in `setup.clj`'s trailing `(comment ...)` block. Wrap any call
   you want called out in `events.svg` in `(region ...)` — e.g. `(region
   (d/pull (d/db conn) '[*] [:item/id 1]))` — and its traffic gets boxed in
   the diagram under a `group` labeled with that exact code (same auto-dump
   pattern as `port-owners`, to `(regions-path)`).
5. Stop the tshark capture, then `(require 'process)` and
   `(process/write-diagram! {:since since :ignore-pod-coord? true})` — can
   be run right from the same REPL, no need to switch files. Reads
   `@setup/tshark-log` + `(setup/ports-path)` + `(setup/regions-path)`
   (missing regions file just means no `region` calls that session, i.e. no
   groups), decodes everything, and writes `events.svg`. `:since` drops
   events before a timestamp (same epoch-millis domain as tshark's
   `:timestamp`) — passing the `since` from step 3 skips DynamoDB
   Local/memcached/transactor startup noise. `:ignore-pod-coord?` drops the
   transactor's ~5s pod-coord heartbeat/lease traffic (see "Known item
   shapes" below) — both the request and its paired response, matched
   per-connection since a response carries no `:id` of its own.
6. When done, tear the stack down from `setup.clj`'s trailing
   `(comment ...)` block (`d/delete-database`, then `.destroy` each
   process) — left commented so loading the file never tears down a
   previous session by accident.

## Pipeline (`src/process.clj`)

```
/tmp/tshark.log (tshark EK-JSON, one packet per line)
  -> parse JSON, drop bulk-index lines and zero-length TCP packets
  -> dynamo/dynamo-exchanges   (stateful: pairs HTTP request+response into one exchange)
  -> mapcat over memcache/packet->messages for anything that isn't dynamo
     (packet->messages self-filters: returns [] for non-memcache packets too,
     so this one mapcat step is enough to drop plain TCP noise -- no extra
     filter needed)
  -> tag :protocol (:dynamo / :memcache)
  -> decode (protocol-specific, see below)
  -> attribute :from/:to
  -> traffic-diagram/write-svg!
```

`:from`/`:to` attribution is deliberately *not* automatic. Nothing in either
payload names the process behind it (everything is `127.0.0.1`), so we don't
go sniffing with `lsof` inside the pipeline itself — the caller passes a
`port->name` map (which port belongs to which named process). Ports missing
from that map show up individually as `:unknown-<port>`, not lumped into one
`:unknown`. `src/setup.clj` still has an `lsof`-based `port-owners` atom
(`owner`, `refresh-ports!`, `start-port-watcher!`) as a *manual convenience*
for building that map at the REPL — it is not called by the decode pipeline.
An `add-watch` on `port-owners` (defined right after the atom itself)
writes its new state to `(ports-path)` — `@tshark-log` + `.ports.edn`
(default `/tmp/tshark.log.ports.edn`, or `TSHARK_LOG` + `.ports.edn` if set)
— on every change, so it's kept in sync automatically and outlives the REPL
session/processes it was swept from; `process.clj` reads it back from disk.
Working against a different capture file is just `(reset! setup/tshark-log
"/path/to/other.log")` — the next change re-dumps to the new path.

## Decoding DynamoDB traffic (`src/dynamo_inspect.clj`)

DynamoDB Local speaks plain HTTP/1.1 + JSON — tshark has no dedicated
dissector for it, so it's parsed as generic HTTP (operation name is in the
`X-Amz-Target` header, payload is the JSON body).

**Key wire-format fact**: Datomic's dynamo storage backend does NOT send its
value blob as a `:B` (Binary) AttributeValue — it's a `:S` (String), and not
a byte-for-byte Latin-1 mapping of the bytes either. The real bytes are
packed **7 bits at a time, LSB-first**, into a bitstream with no
inter-character padding, so every resulting char stays in codepoint 0-127
(`unpack-7bit-lsb`). Every stored item also carries a literal `"__n":{"N":"1"}`
attribute alongside `id`/`v` on the wire (confirmed in raw capture) —
present on every item seen so far with value `"1"`; likely an item-shape/
storage-format version marker, but not confirmed against Datomic source.

Decode pipeline, applied in this order (each step is a no-op passthrough for
anything it doesn't recognize — nothing is ever lost, undecoded values just
stay as they arrived):

1. `unwrap-attribute-values` — strip DynamoDB's `{:S ...}`/`{:N ...}`/...
   AttributeValue wrappers down to plain values.
2. `decode-fressian` — for each `:S`/bytes value: unpack 7-bit-LSB, then
   - if it starts with fressian's `RESET_CACHES` byte (`0xFE`) or gzip magic
     (`0x1F 0x8B`) -> gzip+fressian decode (`fressian-decode.clj`). This is
     what Datomic uses for *larger* values (tx log segments, db-root, etc).
   - else -> try strict UTF-8 decode + `edn/read-string`. Smaller values
     (e.g. the database catalog entry) are written as plain packed
     printed-form text, skipping fressian+gzip entirely.
3. `decode-edn` — some decoded values are themselves *strings* that are
   printed-form EDN (e.g. `pod-coord`'s `:key`, a stringified vector).
   `postwalk`s the body and `edn/read-string`s any string that reads as an
   EDN **collection** (vector/list/map/set) — deliberately not any string
   that reads as EDN at all, because plenty of plain `:S` values (ids, revs)
   are individually valid EDN scalars (`"219"` -> a number, `"pod-coord"` ->
   a symbol) without being intentionally-encoded data.
4. `decode-opaque-base64` — rewrites standard-base64 strings whose decoded
   bytes aren't printable text into hex (e.g. the two 32-byte session/hash
   ids inside `pod-coord`'s `:key`, which are `:db.type/bytes` per Datomic's
   own schema — random tokens or hash digests, not text).

### Known item shapes seen in a real capture

- **`pod-coord`**: `id="pod-coord"`, `:rev N`, `:key [host pid id1 id2 ts
  version flag generation]` (id1/id2 are the 32-byte opaque ids above).
  Written roughly every 5s via `Expected {:rev {:Value N-1}}` conditional
  PutItem (optimistic-concurrency CAS, rev+1 each write) — transactor
  heartbeat/lease record, used for leader election/fencing.
- **`pod-catalog`**: `id="pod-catalog"`, `:rev`, `:tail <id>` — just a
  pointer at the id of the actual catalog-entry item (linked-list head).
- **catalog entry** (the id `pod-catalog` points at): `{"<db-name>"
  {:db-id "<internal-storage-id>"}, :datomic/deleted #{}}` — name -> internal
  id registry, written by `(d/create-database ...)`.
- **db-root**: `{:eavt-main/:aevt-main/:avet-main/:raet-main <uuid>,
  :birth-level, :schema-level, :buildRevision, :rev, :version, ...}` — index
  root pointers.
- **tx log segment**: `{:id <uuid>, :t <t>, :data [#datum [...] ...]}`.

## Decoding memcache traffic (`src/memcache_inspect.clj`)

Binary memcache protocol, tshark has a real dissector for it.
`packet->messages` turns one tshark packet into a seq of
`{:type :request/:response :memcache {...} :opaque ... :stream ...}` maps
(a frame can carry several PDUs). `memcache/decode-fressian` fressian-decodes
storage values the same way as dynamo's, minus the 7-bit unpacking (memcache
values are raw bytes, not string-packed).

## Rendering (`src/traffic_diagram.clj`)

`events->plantuml` / `write-svg!` turn the merged, decoded event list into a
PlantUML sequence diagram, matching the color palette of Datomic's own
"Datomic Architecture" slide:
- **pink `#FFAEFB`** — Storage Service (dynamo) messages.
- **yellow `#FDFF94`** — Cache (memcache) messages.
- A `legend top left` block spells this out on the diagram itself.

`events->plantuml`'s `:regions` opt (`[{:label ... :start ms :end ms}]`, same
shape `setup.clj`'s `region` macro dumps) boxes any events whose `:timestamp`
falls in `[:start :end]` under a PlantUML `group <label> ... end`, so a
REPL call you wrapped in `(region ...)` shows up as one labeled box instead
of loose arrows. Regions are assumed disjoint — sequential `region` calls
naturally are — overlapping windows aren't nested, they render wrong.

Responses that carry nothing but a status code (dynamo: empty `:body`;
memcache: only `:command`+`:status`, e.g. a plain `stored`/`deleted` reply)
get their status inlined onto the arrow label instead of a separate note —
there's nothing else worth showing.

## Gotchas / things not to redo

- Don't add an `lsof`/dynamic port-ownership lookup *inside* the decode
  pipeline — `port->name` is deliberately caller-supplied (see above).
- `decode-edn`'s `coll?` restriction is load-bearing, not defensive — do not
  relax it to "any valid edn string".
- `note-lines`/`default-label` special-case status-only responses; don't
  reintroduce a status-only note.
- `process.clj`'s pipeline is a real function (`write-diagram!`), not
  scratch code — but its bottom `(comment ...)` block (example calls) is
  still never auto-executed.
- `setup.clj` has no `-main` and never starts just one of
  dynamodb/memcached/transactor — loading the namespace starts all three.
  Don't reintroduce per-service entry points; `pids`/the port mapping only
  make sense once all three exist.
