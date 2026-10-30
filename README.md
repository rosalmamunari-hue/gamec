# gamec: a game shield for TCP games (Android + iOS)

The game connects to a local port on the phone. The SDK relays that connection over pinned TLS 1.3 to one
of several **edge nodes**, which forward it to the **origin** (the real game server). Players never learn
the origin address, and the origin can accept connections from the nodes only.

```
 game ──TCP──▶ 127.0.0.1:port ──TLS 1.3, key pinned, token──▶ edge node ──TCP──▶ origin
                  (SDK)                                          (edge/)
```

Nodes are found through **signed DNS TXT records**, so a node can be replaced without shipping a new app,
and no server of your own is needed for discovery.

| Directory | What it is |
|---|---|
| `edge/` | The edge node (Go), plus the tools below |
| `edge/cmd/gencert` | Makes a node's TLS key and certificate and prints its **pin** |
| `edge/cmd/signlist` | Signs the node list **offline** and prints the DNS TXT records; `-check` verifies what is published |
| `edge/cmd/probe` | Checks one deployed node end to end |
| `edge/cmd/soak` | Load and long-connection test (hold, burst, bulk) with a built-in echo origin |
| `android-sdk/` | Android library (Kotlin, minSdk 29) |
| `ios-sdk/` | iOS Swift package (iOS 15+) |
| `control/` | Optional control service for tokens and node lists (not needed with DNS discovery) |

## How a connection is made

1. The SDK asks DNS for the TXT records at your name (DoT and DoH to public resolvers, by IP address, raced;
   the first answer whose **signature verifies** wins).
2. It measures the nodes and picks the fastest healthy one.
3. It asks that node for a short-lived **token** (`GET-TOKEN <device id>`), over pinned TLS.
4. It opens the relay: pinned TLS 1.3, then the token. The node checks the token and connects to the origin.
5. If no node can be reached, the SDK retries for 15 s with backoff while the game's socket stays open.

What protects what: TLS 1.3 encrypts; **key pinning** stops a fake node; the **token** (HMAC, 4 min) keeps
anonymous traffic off the origin; the **signature** on the node list stops DNS tampering from steering
players; per-IP connection limits and per-IP/per-device token limits slow abuse.

## Setting up a node

```sh
cd edge
go run ./cmd/gencert -host <node ip> -out certs/node1          # prints the pin
go build -o edge .
./edge -listen :30800 -origin <origin host:port> \
       -cert certs/node1/cert.pem -key certs/node1/key.pem -secret <shared secret>
```

Run it as a service (systemd `Restart=always`). Useful flags: `-max-per-ip`, `-token-ip-limit`,
`-token-device-limit`, `-banned <file of device ids>`. The same `-secret` must be on every node.
**Make the origin accept connections from the nodes only**, otherwise nothing is hidden.

## Publishing the node list

```sh
cd edge
go run ./cmd/signlist -gen-key list.key           # once; prints the PUBLIC key for the app
# nodes.json: [{"host":"1.2.3.4","port":30800,"pin":"<pin from gencert>"}, ...]
go run ./cmd/signlist -key list.key -nodes nodes.json -valid-days 30
```

Add every printed `gs1:...` line as a **TXT record under one name** (e.g. `_gs.example.com`, TTL 60).
Check what the world sees: `go run ./cmd/signlist -check _gs.example.com -pub <public key>`.

* `list.key` signs the list. **Keep it on your own computer, never on a server**, and back it up: losing it
  means a new key and a new app release.
* The list **expires** (`-valid-days`). Sign and publish again before that, or apps will find no nodes.
* Apps never accept an older list than one they have already seen.

## Using the SDK

**Android**

```kotlin
val discovery = DiscoveryConfig(
    name = "_gs.example.com",
    publicKey = "<public key from signlist -gen-key>",
    deviceId = DeviceId.getOrCreate(context),
    store = PrefsListStore(context),            // keeps the last good list across restarts
)
val shield = ShieldClient(ShieldConfig(discovery = discovery, listener = object : ShieldListener {
    override fun onRetrying(attempt: Int) { /* show "reconnecting" */ }
}))
val port = shield.start()
// connect the game's TCP socket to 127.0.0.1:port instead of the real server
```

**iOS**

```swift
let discovery = try DiscoveryConfig(name: "_gs.example.com",
                                    publicKey: "<public key>",
                                    deviceId: DeviceID.getOrCreate(),
                                    store: UserDefaultsListStore())
let shield = ShieldClient(config: ShieldConfig(discovery: discovery, listener: self))
let port = try shield.start()
```

`ShieldConfig` can instead take a fixed `nodes` list with your own `tokenProvider`, or a `control` service.

Settings worth knowing: `connectRetryWindow` (default 15 s), `deadAfterUnanswered` (default 20 s: a connection
that was sent data and heard nothing back is closed so the game reconnects; set 0 if your protocol can go
that long without replies), `dohProviders` / `dotServers` (IP addresses; add one that works where your
players are, e.g. `223.5.5.5` in mainland China).

**Reconnecting.** The SDK keeps a *new* connection coming; it cannot move a *live* one to another node,
because the node-to-origin leg dies with the node. The game must reconnect when its socket closes.
Android requires the `INTERNET` permission (the library declares it). On iOS the local proxy stops when
the app is suspended; call `start()` again in the foreground.

## Tests

| What | How |
|---|---|
| Node, signing tool, control service | `cd edge && go test ./...` and `cd control && go test ./...` |
| Android unit + local end-to-end | CI (`.github/workflows/ci.yml`) |
| Android on a device or emulator | CI builds the test APK; run it with `am instrument` (see `DeviceTest.kt` for the arguments) |
| iOS | `codemagic.yaml` on a Mac runner (`swift test`) |
| A deployed node | `go run ./cmd/probe -addr host:30800 -pin <pin> -secret <secret>` |
| Long connections and load | `edge/cmd/soak` (see its header; point a node at `soak -echo` as origin) |

## Known limits

* No UDP; no multiplexing of several game connections over one tunnel.
* A device id proves nothing about the player. Abuse control is rate limits and a ban list; real accounts
  would need a login-aware token service (`control/` is the place for that).
* The nodes are ordinary servers. **They do not absorb a large DDoS**; for that, put them behind your cloud
  provider's anti-DDoS product. The SDK and protocol do not replace scrubbing capacity.
* Not yet tested on iOS devices or simulators, on Android older than 15, or from mainland-China networks.
* Cleartext HTTP to the control service is for tests only; use HTTPS.
