# learn-datomic-caching

Goal: understand exactly what Datomic's transactor and peer say to their
storage backend and to memcached, by capturing the raw TCP traffic and
turning it into a readable sequence diagram (an SVG).

Local stack: a Datomic transactor, backed by **DynamoDB Local** (not real
AWS) for storage, plus a local **memcached** for the transactor's
object cache, plus this JVM acting as the peer. Everything runs on
`127.0.0.1`, on different ports (8000 = DynamoDB Local, 11211 = memcached).

Historical note: the project *started* with Postgres as the storage
backend, with an earlier generation of inspection code, before pivoting to
DynamoDB Local. That code, and a later `process`/`protocol`/`dynamodb`/
`memcache` namespace split, have since been removed — current behavior
lives entirely in `src/setup.clj` + `src/tshark.clj` + `src/diagram.clj` +
`src/fressian_decode.clj`, described below.

## File layout

- **`src/setup.clj`** — starts/stops the local stack (DynamoDB Local,
  memcached, transactor), tracks port ownership and labeled time regions,
  and holds the REPL script (its trailing `(comment ...)` block) that
  drives a peer through the Datomic API.
- **`src/tshark.clj`** — the decode pipeline: turns tshark's raw capture
  log into typed, decoded Datomic-traffic events, and `draw-diagram!`,
  the one function that ties the whole thing together into an SVG.
- **`src/diagram.clj`** — turns a list of decoded events into a PlantUML
  sequence diagram (`events->plantuml`) and renders it to SVG
  (`write-svg!`). No protocol-specific knowledge.
- **`src/fressian_decode.clj`** — decodes Datomic's own gzip+fressian
  wire format (tx log segments, db-root, index nodes, ...), used by both
  the DynamoDB and memcache decode paths in `tshark.clj`.

## Running it end to end

1. `scripts/setup.sh` — one-time install of memcached, Datomic Pro,
   DynamoDB Local, tshark, and generation of the transactor config.
2. Start a capture *before* loading `setup.clj` (tshark needs to be
   running first to see the initial TCP handshakes):
   ```
   scripts/capture.sh [path]
   ```
   Writes to `path` if given, else `$TSHARK_LOG`, else `/tmp/tshark.log`.
   Leave it running in its own terminal; stop it with Ctrl-C once you're
   done with step 4.
3. `clj -M:setup` (or load `src/setup.clj` in your editor's REPL) loads
   the namespace's top-level defs — `pids`/`port-owners`/`regions` atoms,
   the `region` macro, `start-all!`/`stop-all!` — but does **not** start
   anything by itself; there's no `-main`. Then, from its trailing
   `(comment ...)` block:
   ```clojure
   (def session (start-all! (or (System/getenv "TSHARK_LOG") "/tmp/tshark.log")))
   ```
   starts DynamoDB Local, memcached, and the transactor together (they
   only make sense as a set — `pids`/the port mapping built from them
   needs all three), connects a peer, and transacts a small schema.
   `start-all!` also kicks off `start-port-watcher!`, which keeps
   `port-owners` current via periodic `lsof` sweeps for as long as the
   REPL runs, and returns a session map (`:since`, `:tshark-log`, the
   started processes, ...) worth holding onto for later steps.
4. Do your peer work at the REPL (`d/transact`, `d/pull`, `d/q`, ...) —
   see the full sweep of examples already in `setup.clj`'s `(comment
   ...)` block, covering writes, retracts, queries, pull/entity/touch,
   raw datom/index access, `as-of`/`since`/`history`, `with`, and
   `tx-range`. Wrap any call you want called out in the diagram in
   `(region ...)` — e.g. `(region (d/pull (d/db conn) '[*] [:item/id
   1]))` — and its traffic gets boxed under a `group` labeled with that
   exact code. `port-owners`/`regions` are auto-dumped to
   `<tshark-log>.ports.edn` / `<tshark-log>.regions.edn` on every change,
   so they're already on disk whenever you're ready to render.
5. Stop the tshark capture, then render the diagram straight from the
   same REPL:
   ```clojure
   (require 'tshark)
   (tshark/draw-diagram! (:tshark-log session) {:since (:since session)})
   ```
   Reads the log plus its sibling `.ports.edn`/`.regions.edn` files,
   decodes everything, and writes an SVG (default: `<tshark-log>.svg`).
   `:since` (epoch millis, same domain as tshark's own `:timestamp`)
   drops events before that point — passing the session's `:since` skips
   DynamoDB Local/memcached/transactor startup noise. The transactor's
   ~5s `pod-coord` heartbeat/lease traffic (see "Known item shapes"
   below) is dropped by default too, both the request and its paired
   response; pass `{:noisy? (constantly false)}` to keep it. See
   `tshark/draw-diagram!`'s docstring for the rest of its opts
   (`:svg-path`, `:port-names`, `:protocol-styles`).
6. When done, tear the stack down from `setup.clj`'s trailing `(comment
   ...)` block (`d/delete-database`, then `stop-all!`) — left commented
   so loading the file never tears down a previous session by accident.

## Pipeline (`src/tshark.clj`)

```
tshark log (EK-JSON, one packet per line)
  -> parse-tshark    parse JSON, drop bulk-index lines and zero-length TCP
                      packets, match each record to a known protocol
                      (dynamodb/memcache) by port+layer, decode its
                      hex-encoded byte fields, split multi-PDU memcache
                      segments into one record per PDU
  -> parse-datomic-traffic   extract each protocol's typed fields
                      (:operation/:key/:status/:body/...), then decode
                      :body (DynamoDB's 7-bit-packed blobs / memcache's raw
                      fressian bytes)
  -> remove-noise    stateful transducer: drops noisy requests (by default,
                      the pod-coord heartbeat) together with their paired
                      response, matched per-stream FIFO
  -> diagram/write-svg!
```

Each of `parse-tshark`, `parse-datomic-traffic`, and `remove-noise`
follows the same two-arity convention as `clojure.core/map`/`filter`:
called with no trailing collection, they return a transducer (for
composing into a `comp` chain); called with a trailing collection, they
apply it directly and return the resulting lazy seq. `tshark/draw-diagram!`
is the function that runs the whole chain end to end and hands the
result to `diagram/write-svg!`.

`:from`/`:to` attribution is deliberately *not* automatic. Nothing in
either payload names the process behind it (everything is `127.0.0.1`),
so the decode pipeline doesn't go sniffing with `lsof` itself — it takes
a `port->name` map (`draw-diagram!`'s `:port-names`, merged with the
`.ports.edn` file and the built-in DynamoDB/memcache server-port
defaults). Ports missing from that map show up individually as
`:unknown-<port>`, not lumped into one `:unknown`. `src/setup.clj`'s
`lsof`-based `port-owners` atom (`owner`, `refresh-ports!`,
`start-port-watcher!`) is a *manual convenience* for building that map at
the REPL — it is not called by the decode pipeline itself.

## Decoding DynamoDB traffic

DynamoDB Local speaks plain HTTP/1.1 + JSON — tshark has no dedicated
dissector for it, so it's parsed as generic HTTP (operation name is in
the `X-Amz-Target` header, payload is the JSON body). Note: because
`:operation` only ever comes from that request-only header, response
events have no `:operation` of their own and render generically (e.g.
`"200"` rather than `"PutItem 200"`) — there's no wire-level signal to
recover it from.

**Key wire-format fact**: Datomic's dynamo storage backend does NOT send
its value blob as a `:B` (Binary) AttributeValue — it's a `:S` (String),
and not a byte-for-byte Latin-1 mapping of the bytes either. The real
bytes are packed **7 bits at a time, LSB-first**, into a bitstream with
no inter-character padding, so every resulting char stays in codepoint
0-127 (`unpack-7bit-lsb`).

Decode pipeline, applied in this order (each step is a no-op passthrough
for anything it doesn't recognize — nothing is ever lost, undecoded
values just stay as they arrived):

1. `unwrap-attribute-values` — strip DynamoDB's `{:S ...}`/`{:N ...}`/...
   AttributeValue wrappers down to plain values.
2. `decode-dynamo-body` — for each ASCII-7 string value: unpack 7-bit-LSB,
   then
   - if the unpacked bytes look like a fressian body (`fressian-body?`)
     -> gzip+fressian decode (`fressian-decode.clj`). This is what
     Datomic uses for *larger* values (tx log segments, db-root, etc).
   - else -> try strict UTF-8 decode + `edn/read-string`. Smaller values
     (e.g. the database catalog entry) are written as plain packed
     printed-form text, skipping fressian+gzip entirely.
3. `decode-edn` — some decoded values are themselves *strings* that are
   printed-form EDN (e.g. `pod-coord`'s `:key`, a stringified vector).
   `postwalk`s the body and `edn/read-string`s any string that reads as
   an EDN **collection** (vector/list/map/set) — deliberately not any
   string that reads as EDN at all, because plenty of plain `:S` values
   (ids, revs) are individually valid EDN scalars (`"219"` -> a number,
   `"pod-coord"` -> a symbol) without being intentionally-encoded data.

### Known item shapes seen in a real capture

- **`pod-coord`**: `id="pod-coord"`, `:rev N`, `:key [host pid id1 id2 ts
  version flag generation]`. Written roughly every 5s via `Expected
  {:rev {:Value N-1}}` conditional PutItem (optimistic-concurrency CAS,
  rev+1 each write) — transactor heartbeat/lease record, used for leader
  election/fencing.
- **`pod-catalog`**: `id="pod-catalog"`, `:rev`, `:tail <id>` — just a
  pointer at the id of the actual catalog-entry item (linked-list head).
- **catalog entry** (the id `pod-catalog` points at): `{"<db-name>"
  {:db-id "<internal-storage-id>"}, :datomic/deleted #{}}` — name ->
  internal id registry, written by `(d/create-database ...)`.
- **db-root**: `{:eavt-main/:aevt-main/:avet-main/:raet-main <uuid>,
  :birth-level, :schema-level, :buildRevision, :rev, :version, ...}` —
  index root pointers.
- **tx log segment**: `{:id <uuid>, :t <t>, :data [#datum [...] ...]}`.

## Decoding memcache traffic

Binary memcache protocol, tshark has a real dissector for it.
`split-memcache-messages` turns one tshark packet into a seq of one
record per PDU (a single TCP segment can carry several). `memcache-fields`
extracts `:operation` (via `opcode->command`), `:status` (via
`status->outcome`), `:key`, and the raw value bytes; `decode-body`
fressian-decodes those bytes the same way as dynamo's larger values,
minus the 7-bit unpacking (memcache values are raw bytes, not
string-packed).

## Rendering (`src/diagram.clj`)

`events->plantuml` / `write-svg!` turn the merged, decoded event list
into a PlantUML sequence diagram, matching the color palette of
Datomic's own "Datomic Architecture" slide:
- **pink `#FFAEFB`** — Storage Service (DynamoDB) messages.
- **yellow `#FDFF94`** — Cache (memcached) messages.
- A `legend top left` block spells this out on the diagram itself.

`:regions` (`[{:label ... :start ms :end ms}]`, same shape `setup.clj`'s
`region` macro dumps) boxes any events whose `:timestamp` falls in
`[:start :end]` under a PlantUML `group <label> ... end`, so a REPL call
you wrapped in `(region ...)` shows up as one labeled box instead of
loose arrows. Regions are assumed disjoint — sequential `region` calls
naturally are — overlapping windows aren't nested, they render wrong.

Responses that carry nothing but a status code (dynamo: empty `:body`;
memcache: only `:operation`+`:status`, e.g. a plain `stored`/`deleted`
reply) get their status inlined onto the arrow label instead of a
separate note — there's nothing else worth showing.

## Gotchas / things not to redo

- Don't add an `lsof`/dynamic port-ownership lookup *inside* the decode
  pipeline — `port->name` is deliberately caller-supplied (see above).
- `decode-edn`'s `coll?` restriction is load-bearing, not defensive — do
  not relax it to "any valid edn string".
- `default-label`/`note-lines` special-case status-only responses; don't
  reintroduce a status-only note.
- DynamoDB responses rendering as e.g. `"200"` instead of `"PutItem 200"`
  is expected, not a bug — `:operation` genuinely has no response-side
  source (see "Decoding DynamoDB traffic" above). Don't try to
  reconstruct it by tagging a shared id across request/response; that
  was considered and deliberately dropped.
- `tshark.clj`'s `parse-tshark`/`parse-datomic-traffic`/`remove-noise`
  all follow the `map`/`filter` two-arity (transducer-or-seq-fn)
  convention — keep new pipeline steps consistent with it.
- `setup.clj` has no `-main` and never starts just one of
  dynamodb/memcached/transactor — `start-all!` starts all three
  together. Don't reintroduce per-service entry points; `pids`/the port
  mapping only make sense once all three exist.
