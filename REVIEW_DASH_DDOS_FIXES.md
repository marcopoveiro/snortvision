# SnortVision v0.1 review — dashboard / DDoS / map fixes

## Main issues found

1. The frontend only polled `/api/alerts/new`, so old alerts already in SQLite were never loaded into the UI.
2. `normaliseAlert()` expected raw Snort JSON, but the backend returns DB rows with `ts`, `rule`, `severity`, and `category` already populated.
3. The DDoS page was still demo-oriented and did not render real backend DDoS alerts as the primary source.
4. Existing stored alerts could have non-normalized timestamps and empty GeoIP fields, which breaks recency counters and the map.
5. `geoip-lite` was optional, so some local installs ended up with no country enrichment and an empty map.

## Fixes applied

- Added initial alert hydration from `/api/alerts?limit=500`
- Fixed alert normalization for both raw Snort JSON and backend DB/API rows
- Changed blocklist refresh to polling every 5 seconds
- Reworked the DDoS tab to show:
  - recent real DDoS alerts
  - top real DDoS source IPs
  - mitigation actions derived from the real blocklist
- Added backend timestamp normalization for Snort classic timestamps like `03/12-10:48:27.123456`
- Added backend migration to normalize stored alert timestamps and enrich missing GeoIP values
- Promoted `geoip-lite` from optional dependency to normal dependency

## Deploy note

After replacing the project, run backend dependency install again so `geoip-lite` is present:

```bash
cd backend
npm install
```

Then restart the backend.
