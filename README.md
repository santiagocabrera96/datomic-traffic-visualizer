# learn-datomic-caching

Goal: understand exactly what Datomic's transactor and peer say to their
storage backend and to memcached, by capturing the raw TCP traffic and
turning it into a readable sequence diagram (an SVG).

Local stack: a Datomic transactor, backed by **DynamoDB Local** (not real
AWS) for storage, plus a local **memcached** for the transactor's object
cache, plus this JVM acting as the peer. Everything runs on `127.0.0.1`, on
different ports (8000 = DynamoDB Local, 11211 = memcached).

## Quick start

1. Setup (one-time install of memcached/tshark, Datomic
   Pro, and DynamoDB Local).
```
./scripts/setup.sh
```
2. In a terminal, run 
```
scripts/capture.sh
```
and leave it running.
3. While it runs, run 
```
clj -M demo.clj
``` 
in another terminal.
4. Once `demo.clj` finishes, stop the capture (Ctrl-C).

See "Running it end to end" below for details on each step.

## File layout

`src/` is split into reusable, Datomic-agnostic pieces (parsing a tshark
capture, decoding a protocol, decoding fressian, rendering a diagram) and
one example layer (`datomic_caching.clj`) that knows about Datomic
specifically. Every file ends with a trailing `(comment ...)` block meant
for REPL-driven, form-by-form exploration.

- **`src/tshark.clj`** — parses a tshark `-T json`/`ek` capture into
  TCP-layer events (`read-tshark`), plus `remove-noise` for dropping
  paired noisy request/response traffic (e.g. a heartbeat). Knows nothing
  about any specific protocol: `decode-protocol` is an open multimethod,
  and only `:tcp`/`:default` are registered here.
- **`src/memcache.clj`**, **`src/http.clj`**, **`src/dynamodb.clj`** — each
  requires `tshark` (not the other way around) and registers its own
  `decode-protocol` method at the bottom of the file, so adding a protocol
  is just requiring its namespace — `tshark.clj` itself never needs
  editing. `dynamodb.clj` in turn requires `http.clj`, since DynamoDB Local
  speaks plain HTTP/JSON and is decoded as an enrichment of an already-
  decoded HTTP event.
- **`src/fressian_decode.clj`** — decodes Datomic's gzip+fressian wire
  format; `decode-body` takes an optional `readers` map
  (`{tag-string (fn [tag form] ...)}`) for customizing how specific
  fressian tags decode, rather than a global multimethod, so different
  callers' tag decodings can't stomp on each other.
- **`src/diagram.clj`** — pure rendering: `events->plantuml`/
  `write-diagram!`/`write-svg!` turn a seq of events into a PlantUML
  sequence diagram / SVG. Events must already carry `:from`/`:to`/`:color`
  — nothing here knows about ports, protocols, or Datomic.
- **`src/datomic_caching.clj`** — the actual example: reads a tshark
  capture, decodes it through memcache/http/dynamodb, drops the
  transactor's heartbeat noise, decodes Datomic's own fressian-tagged
  shapes (index nodes, pod-coord, packed values), and styles/colors each
  event for the diagram. Deliberately kept separate from the reusable
  pieces above — it's the one place that knows which ports/colors/Datomic
  shapes matter for *this* use case.
- **`src/utils.clj`** — small pure helpers (`->vec`, `some-vals`,
  `hex-payload->bytes`, `update-in-if-present`, `unpack-7bit-lsb`).
- **`src/setup.clj`** — starts/stops the local stack (DynamoDB Local,
  memcached, transactor), tracks port ownership and labeled time regions
  via `lsof` sweeps, and dumps both to `<tshark-log>.ports.edn`/
  `.regions.edn` on every change so a later render can read them back.
- **`demo.clj`** (repo root) — the unattended entry point: sweeps the
  Datomic peer API end to end and renders the result. See below.

## Running it end to end

1. `scripts/setup.sh` — one-time install of memcached and tshark (via
   Homebrew), download of Datomic Pro and DynamoDB Local, and generation
   of the transactor config pointing at DynamoDB Local + memcached. Safe
   to re-run; each step skips work it's already done.
2. Start a capture *before* starting the stack, so tshark sees the initial
   TCP handshakes too:
   ```
   scripts/capture.sh [path]
   ```
   Writes to `path` if given, else `$TSHARK_LOG`, else `/tmp/tshark.log`.
   Leave it running in its own terminal; stop it with Ctrl-C once the run
   below has produced its diagram.
3. Run the demo, either:
   - **In the terminal**, all at once: `clj -M demo.clj` — starts the
     stack, sweeps the Datomic peer API, renders the diagram, and tears
     the stack back down, then exits.
   - **In the REPL**, step by step: load `src/setup.clj`, then work
     through its trailing `(comment ...)` block one form at a time — it
     runs the same forms as `demo.clj` (minus the leading `require`), so
     you get the same run but decide what to run and when, and can poke
     around in between (your own `d/q`/`d/pull` calls, inspecting
     `db`/`conn`, etc.) before rendering.

   Either way, `demo.clj`:
   - calls `(start-all! tshark-log-file)`, which starts DynamoDB Local,
     memcached, and the transactor together (there's no partial start —
     `pids`/the port mapping only make sense once all three exist), then
     connects a peer and transacts a small schema.
   - sweeps the rest of the Datomic peer API — more writes, retracts,
     `d/q`, `d/pull`/`d/pull-many`/`d/touch`, raw `d/datoms`/
     `d/index-range`, `d/as-of`/`d/since`/`d/history`, `d/with`,
     `d/tx-range`, and an explicit `d/request-index` (to force an
     indexing job, rather than waiting on its usual schedule, so the
     capture sees the segments it writes to memcache beforehand) — each
     call wrapped in `setup`'s `region` macro, which boxes its traffic
     under a labeled `group` in the diagram.
   - renders the diagram via `datomic-caching/read-datomic-capture`
     (reads the tshark log, decodes it, drops pod-coord/pod-standby
     heartbeat noise, decodes Datomic's known fressian shapes) piped
     through `event->draw`/`attach-participants` (adds `:tag`/`:note`/
     `:color`/`:from`/`:to` per event) into `diagram/write-svg!`.
     Port names and regions are read back from `:ports-path`/
     `:regions-path` on disk (rather than kept in memory) so the render
     reflects the whole run, not just what was known when `start-all!`
     returned.
   - tears the stack down (`d/delete-database`, then `stop-all!`).
4. Stop the tshark capture (Ctrl-C) once the diagram's been rendered.

To just see how it looks, steps 2-4 can be run as a single line (capture
starts in the background, `demo.clj` runs in the foreground, then the
capture is killed once it returns):

```
sudo -v; ./scripts/capture.sh & pid=$!; clj -M demo.clj; kill "$pid"
```

To write the capture to a specific path instead of the default
`/tmp/tshark.log`, set `TSHARK_LOG` for that line only (wrapped in
`sh -c` so the whole `;`/`&`-chained sequence sees it):

```
TSHARK_LOG=/tmp/my.log sh -c 'sudo -v; ./scripts/capture.sh & pid=$!; clj -M demo.clj; kill "$pid"'
```

## Tests

`clojure -M:test` runs the whole suite (cognitect test-runner) — there's a
`test/*_test.clj` for every `src/*.clj` namespace. Run a single namespace
with `clojure -M:test -n <namespace>`.

## Decoding DynamoDB traffic

DynamoDB Local speaks plain HTTP/1.1 + JSON — tshark has no dedicated
dissector for it, so `dynamodb.clj` decodes it as HTTP first (operation
name from the `X-Amz-Target` header, key from the request body's `:Item`/
`:Key` AttributeValue map) and enriches from there. Because `:operation`
only ever comes from that request-only header, response events have no
operation of their own and render generically (e.g. `"200"` rather than
`"PutItem 200"`) — there's no wire-level signal to recover it from.

**Key wire-format fact**: Datomic's dynamo storage backend does NOT send
its value blob as a `:B` (Binary) AttributeValue — it's a `:S` (String),
and not a byte-for-byte Latin-1 mapping of the bytes either. The real
bytes are packed **7 bits at a time, LSB-first**, into a bitstream with no
inter-character padding, so every resulting char stays in codepoint 0-127
(`utils/unpack-7bit-lsb`). `datomic-caching/decode-datomic-known-shapes`
unpacks and fressian-decodes any row keyed by a UUID this way.

### Known item shapes seen in a real capture

Handled specially by `decode-datomic-known-shapes`:

- **`pod-coord`/`pod-standby`**: the transactor's heartbeat/lease rows,
  identified by `:id`. Their `:key` is a printed-form EDN *vector* (e.g.
  `"[host pid transactor-id peer-id ts version flag generation]"`), undone
  with `edn/read-string` rather than fressian — these are also the rows
  `read-datomic-capture` drops by default as noise (`remove-noise`), since
  they repeat every few seconds and drown out everything else.
- **any row keyed by a UUID**: its `:v` is 7-bit-LSB packed then
  fressian-encoded (see above) — this is where the tx log segments,
  db-root, and index nodes below actually live.

Handled by `datomic-index-readers` (passed into `fressian-decode/decode-body`),
because Datomic stores these column-wise (one array per field) rather than
row-wise, and a human skimming the diagram wants rows:

- **`index-tdata`**: parallel `[v e a t added]` column arrays, zipped back
  into a vector of `{:e :a :v :t :added}` datom maps.
- **`index-dir-node`** / **`index-root-node`**: an `index-tdata` (used
  just for its first datom per child) plus parallel segment-id/datom-count
  (dir node) or dir-id (root node) columns, zipped into
  `{:first-datom :seg-id :datom-count}` / `{:first-datom :dir-id}` rows.

## Decoding memcache traffic

Binary memcache protocol — tshark has a real dissector for it, parsing
each PDU's header fields but leaving the payload as one undifferentiated
byte blob for the whole TCP segment (which can coalesce several PDUs
back-to-back). `memcache/tshark-tcp->memcache` slices each PDU's value
bytes out by hand, using tshark's `total_body_length` (extras+key+value)
per PDU and a running offset to find where each one starts on the wire.
Values are fressian-decoded the same way as DynamoDB's larger values,
minus the 7-bit unpacking — memcache values are raw bytes, not
string-packed.

## Rendering (`src/diagram.clj`)

`events->plantuml`/`write-svg!` turn a seq of events (each already
carrying `:from`/`:to`/`:color`, and optionally `:note`) into a PlantUML
sequence diagram. `datomic-caching/event->draw` is what actually assigns
those, matching the color palette of Datomic's own "Datomic Architecture"
slide:

- **pink `#FFAEFB`** — DynamoDB (storage) messages.
- **yellow `#FDFF94`** — memcached (cache) messages.
- **blue `#94C9FF`** — plain HTTP messages (no dynamodb layer matched).
- **grey `#D3D3D3`** — bare TCP (no higher protocol decoded), also the
  default when an event carries no `:color` at all.

`event->draw`'s `cond` order matters: on real traffic a dynamodb event is
also an http event (`dynamodb/http->dynamodb` assoc's `:dynamodb` onto an
already-`:http` event) which is also a tcp event, so checking the more
specific protocol first is what makes it draw pink instead of falling
through to blue or grey.

`:from`/`:to` are deliberately *not* derived automatically inside
`diagram.clj` or the decode pipeline — nothing on the wire names the
process behind a port (everything is `127.0.0.1`), so
`datomic-caching/attach-participants` takes a `port->name` map instead (an
unknown port becomes `:unknown-<port>` rather than being silently lumped
together). `setup.clj`'s `lsof`-based port tracking is what builds that
map for a real run, dumped to `<tshark-log>.ports.edn` for a render to
read back later — it's a REPL/demo convenience, not something the decode
or render pipeline calls itself.

`:regions` (`[{:label ... :start ms :end ms}]`, the same shape `setup.clj`'s
`region` macro accumulates) boxes any events whose `:timestamp` falls in
`[:start :end]` under a PlantUML `group <label> ... end`, so a REPL call
wrapped in `(region ...)` shows up as one labeled box instead of loose
arrows. Regions are assumed disjoint — sequential `region` calls naturally
are; overlapping windows aren't nested, they render wrong.

`skinparam wrapWidth` handles normal word-boundary wrapping of note/message
text at render time, but only wraps at whitespace — a whitespace-free run
(e.g. a raw binary blob's escaped bytes) would otherwise blow out the
diagram's width unwrapped, so `diagram.clj` forces its own line breaks into
any such run longer than `:max-line-length` first.
