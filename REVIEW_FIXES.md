# SnortVision v0.1 review fixes

## Fixed in this package
- Reworked the PulledPork3 Oinkcode backend flow to remove the nested shell quoting that was causing:
  - `sh: 1: Syntax error: Unterminated quoted string`
- Switched the Oinkcode update flow to the PulledPork3 config-driven command:
  - `/usr/local/bin/pulledpork3 -c /usr/local/etc/pulledpork/pulledpork.conf -i`
- Auto-install now follows the official PulledPork3 layout:
  - `/usr/local/etc/pulledpork/`
  - `/usr/local/bin/pulledpork/`
  - `/usr/local/bin/pulledpork3`
- Added a standalone install helper script:
  - `scripts/install_pulledpork3_official.sh`
- Added page persistence and Sync panel tab persistence in the frontend.
- Improved the light theme to reduce glare and cover more UI surfaces.
- Added stage reporting (`install`, `configure`, `update`, `reload`) for easier backend troubleshooting.

## Validation performed
- `node --check backend/server.js`
- `bash -n scripts/install_pulledpork3_official.sh`
- JSX parse/bundle check with esbuild for `frontend/src/App.jsx`
