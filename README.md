### `Features`

- Collect SSL/TLS certificate information from target hosts.
- Interactive force-directed graph of hosts, certificates, issuers, SANs and vulnerabilities.
- Root-aware and context-aware vulnerability analysis (expiration, weak crypto, self-signed, hostname mismatch, untrusted issuers, incomplete chain, key usage)
- Intelligent filtering and rate limiting to reduce false positives and noise
- Persistent storage in SQLite (WAL mode)

  <img width="1236" height="696" alt="cert_front" src="https://github.com/user-attachments/assets/43d0f316-991d-4f8f-9096-e4285cd52b03" />
  

### `Installation`

          cd certgraph
          python -m venv .venv
          Windows: .venv\Scripts\activate
          Linux:   source .venv/bin/activate
          pip install -r requirements.txt

### `Usage`

          python certgraph.py or python3 certgraph.py

- Open http://127.0.0.1:8443

### `Configuration`

        Environment variables (prefix `CERTGRAPH_`):

        | Variable | Default | Description |
        |----------|---------|-------------|
        | HOST | 127.0.0.1 | Bind address |
        | PORT | 8443 | Bind port |
        | DB_PATH | data/certgraph.db | SQLite path |
        | MAX_WORKERS | 32 | Concurrent collectors |
        | CONNECT_TIMEOUT | 8.0 | Socket timeout (seconds) |
        | MAX_TARGETS | 500 | Maximum targets per scan |
        | RATE_LIMIT_PER_HOST | 0.15 | Delay between requests to same host |
        | LOG_LEVEL | INFO | Logging level |

### `API`

        - `POST /api/scan` — start scan `{ "targets": ["example.com"], "ports": [443], "analyze_vulns": true }`
        - `GET /api/scan/{id}` — full results + graph
        - `GET /api/scans` — recent scans
        - `WS /ws` — real-time progress and completion events
