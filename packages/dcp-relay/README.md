# @dcprotocol/relay

Encrypted relay for DCP remote and cloud agents.

The relay moves encrypted envelopes between an agent and a local vault. It is transport. Secrets do not belong in relay logs or relay payload metadata.

It serves two paths:

- **Remote/VPS sidecar** — a `dcp-agent` sidecar on a server forwards encrypted envelopes through the relay to the on-device vault.
- **Cloud Connect MCP facade** — for agents you do not host (Claude.ai, ChatGPT, hosted OpenClaw/Hermes), the relay exposes an MCP endpoint with an OAuth bridge. The agent connects using a one-time, key-pinned connect link (`dcp_connect_v1_…`) the user pastes in; the relay carries end-to-end-encrypted requests to the vault, which approves on-device. The relay never sees plaintext — see [`ARCHITECTURE.md`](../../ARCHITECTURE.md) → Cloud Connect Path.

## Run

```bash
npx -y @dcprotocol/relay --port 8422 --host 0.0.0.0
```

Debug mode:

```bash
npx -y @dcprotocol/relay --port 8422 --debug
```

Health check:

```bash
curl -sS http://127.0.0.1:8422/health
```

## Options

```text
--port, -p        Port to listen on
--host, -h        Host to bind
--debug, -d       Enable debug logging
--rate-limit, -r  Requests per minute
--help            Show help
```

## Use It For

- remote agent sidecars
- local remote-agent tests
- staging relay tests

The relay is not the vault. It cannot approve requests or sign transactions by itself.
