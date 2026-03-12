#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/pulledpork3}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin/pulledpork}"
CONF_DIR="${CONF_DIR:-/usr/local/etc/pulledpork}"
VENV_DIR="${VENV_DIR:-${REPO_DIR}/.venv}"
RULES_DIR="${RULES_DIR:-/etc/snort/rules}"
PP_CONF="${PP_CONF:-${CONF_DIR}/pulledpork.conf}"
RULE_PATH="${RULE_PATH:-${RULES_DIR}/snort.rules}"
BLOCKLIST_PATH="${BLOCKLIST_PATH:-${RULES_DIR}/iplists/default.blocklist}"
LOCAL_RULES="${LOCAL_RULES:-${RULES_DIR}/snortvision.rules}"
OINKCODE="${OINKCODE:-}"

if [[ $EUID -ne 0 ]]; then
  echo "Run this script with sudo or as root."
  exit 1
fi

PKG_OK=0
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y git ca-certificates python3 python3-pip python3-venv python3-requests
  PKG_OK=1
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y git ca-certificates python3 python3-pip python3-requests
  PKG_OK=1
elif command -v yum >/dev/null 2>&1; then
  yum install -y git ca-certificates python3 python3-pip python3-requests
  PKG_OK=1
fi

if [[ "$PKG_OK" != "1" ]]; then
  echo "Unsupported package manager"
  exit 2
fi

if [[ -d "$REPO_DIR/.git" ]]; then
  git -C "$REPO_DIR" pull --ff-only
else
  rm -rf "$REPO_DIR"
  git clone https://github.com/shirkdog/pulledpork3.git "$REPO_DIR"
fi

mkdir -p "$CONF_DIR" "$INSTALL_DIR" "$RULES_DIR" "$(dirname "$BLOCKLIST_PATH")"
cp "$REPO_DIR/etc/pulledpork.conf" "$CONF_DIR/"
cp "$REPO_DIR/pulledpork.py" "$INSTALL_DIR/"
rm -rf "$INSTALL_DIR/lib"
cp -r "$REPO_DIR/lib" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/pulledpork.py"
ln -sf "$INSTALL_DIR/pulledpork.py" /usr/local/bin/pulledpork.py

if command -v python3 >/dev/null 2>&1 && python3 -m venv --help >/dev/null 2>&1; then
  rm -rf "$VENV_DIR"
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --upgrade pip wheel >/dev/null 2>&1 || true
  if [[ -f "$REPO_DIR/requirements.txt" ]]; then
    "$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt"
  fi
fi

cat > /usr/local/bin/pulledpork3 <<WRAP
#!/usr/bin/env sh
PY="${VENV_DIR}/bin/python3"
if [ ! -x "\$PY" ]; then
  PY="\$(command -v python3)"
fi
exec "\$PY" "${INSTALL_DIR}/pulledpork.py" "\$@"
WRAP
chmod +x /usr/local/bin/pulledpork3

if [[ -n "$OINKCODE" ]]; then
  TMP_CONF="$(mktemp)"
  cat > "$TMP_CONF" <<CONF
community_ruleset = false
registered_ruleset = false
lightspd_ruleset = true
oinkcode = ${OINKCODE}
rule_mode = simple
ips_policy = connectivity
rule_path = ${RULE_PATH}
blocklist_path = ${BLOCKLIST_PATH}
ignored_files = includes.rules, snort3-deleted.rules
temp_path = /tmp
CONF
  if [[ -f "$LOCAL_RULES" ]]; then
    printf 'local_rules = %s\n' "$LOCAL_RULES" >> "$TMP_CONF"
  fi
  SNORT_BIN="$(command -v snort 2>/dev/null || command -v snort3 2>/dev/null || true)"
  if [[ -n "$SNORT_BIN" ]]; then
    printf 'snort_path = %s\n' "$SNORT_BIN" >> "$TMP_CONF"
  fi
  cp "$TMP_CONF" "$PP_CONF"
  rm -f "$TMP_CONF"
fi

/usr/local/bin/pulledpork3 -V
if [[ -n "$OINKCODE" ]]; then
  /usr/local/bin/pulledpork3 -c "$PP_CONF" -i
fi
