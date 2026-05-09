# @dcprotocol/relay

Encrypted relay for DCP remote agents.

The relay moves encrypted envelopes between a remote sidecar and a local vault. It is transport. Secrets do not belong in relay logs or relay payload metadata.

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
