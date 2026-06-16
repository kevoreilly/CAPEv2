#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# CAPEv2 Ansible Deploy Wrapper
# Syntax-check → dry-run → confirmation → execute
# ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAYBOOK="${ANSIBLE_PLAYBOOK:-site.yml}"
INVENTORY="${ANSIBLE_INVENTORY:-${SCRIPT_DIR}/inventory/hosts.ini}"
VAULT_PASS="${ANSIBLE_VAULT_PASS:-${SCRIPT_DIR}/.vault_pass}"
ANSIBLE_EXTRA=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

  Deploy CAPEv2 using Ansible with safety checks.

Options:
  -p, --playbook FILE     Playbook to run (default: site.yml)
  -i, --inventory FILE    Inventory file  (default: inventory/hosts.ini)
  -v, --vault-pass FILE   Vault password file (default: .vault_pass)
  -l, --limit HOSTS       Limit execution to specific hosts/groups
  -t, --tags TAGS         Only run tasks with these tags (comma-separated)
      --skip-tags TAGS    Skip tasks with these tags (comma-separated)
      --check             Only run syntax + dry-run, do NOT execute
      --diff             Show diff output
      --list-tags        List available tags and exit
  -e, --extra-var K=V     Set extra Ansible variable (can be repeated)
  -h, --help              Show this help

Environment overrides:
  ANSIBLE_PLAYBOOK, ANSIBLE_INVENTORY, ANSIBLE_VAULT_PASS

Examples:
  $(basename "$0")                              # Full deploy with confirmation
  $(basename "$0") --check                      # Syntax + dry-run only
  $(basename "$0") -t optional                  # Only optional components
  $(basename "$0") --skip-tags optional         # Skip optional components
  $(basename "$0") -l cape-host01               # Single host
  $(basename "$0") -p playbooks/host-deploy.yml # Specific playbook
EOF
    exit 0
}

# ── Argument parsing ────────────────────────────────────────────────
CHECK_ONLY=false
DIFF=""
LIST_TAGS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        --check) CHECK_ONLY=true ;;
        --diff) DIFF="--diff" ;;
        --list-tags) LIST_TAGS=true ;;
        -p|--playbook) shift; PLAYBOOK="$1" ;;
        -i|--inventory) shift; INVENTORY="$1" ;;
        -v|--vault-pass) shift; VAULT_PASS="$1" ;;
        -l|--limit) shift; ANSIBLE_EXTRA+=("--limit" "$1") ;;
        -t|--tags) shift; ANSIBLE_EXTRA+=("--tags" "$1") ;;
        --skip-tags) shift; ANSIBLE_EXTRA+=("--skip-tags" "$1") ;;
        -e|--extra-var) shift; ANSIBLE_EXTRA+=("--extra-vars" "$1") ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# ── Resolve paths ──────────────────────────────────────────────────
PLAYBOOK_PATH="${SCRIPT_DIR}/${PLAYBOOK}"
INVENTORY_PATH="${INVENTORY}"
VAULT_PASS_PATH="${VAULT_PASS}"

# Allow absolute/relative paths for inventory & vault
[[ "$PLAYBOOK" != /* ]] && PLAYBOOK_PATH="${SCRIPT_DIR}/${PLAYBOOK}"
[[ "$INVENTORY" != /* ]] && INVENTORY_PATH="${SCRIPT_DIR}/${INVENTORY}"
[[ "$VAULT_PASS" != /* ]] && VAULT_PASS_PATH="${SCRIPT_DIR}/${VAULT_PASS}"

# ── Pre-flight checks ──────────────────────────────────────────────
errors=0
if [[ ! -f "$PLAYBOOK_PATH" ]]; then
    echo "ERROR: Playbook not found — $PLAYBOOK_PATH" >&2
    errors=$((errors + 1))
fi
# Inventory may be a file or an ad-hoc comma list (e.g. localhost,)
if [[ "$INVENTORY_PATH" != *,* ]] && [[ ! -f "$INVENTORY_PATH" ]]; then
    echo "ERROR: Inventory not found — $INVENTORY_PATH" >&2
    errors=$((errors + 1))
fi
if [[ ! -f "$VAULT_PASS_PATH" ]] && [[ -f "${SCRIPT_DIR}/.vault_pass" ]]; then
    VAULT_PASS_PATH="${SCRIPT_DIR}/.vault_pass"
elif [[ ! -f "$VAULT_PASS_PATH" ]]; then
    echo "ERROR: Vault password file not found — $VAULT_PASS_PATH" >&2
    echo "  Create it:  echo -n 'your-vault-password' > ${SCRIPT_DIR}/.vault_pass" >&2
    errors=$((errors + 1))
fi
[[ $errors -gt 0 ]] && exit 1

cd "$SCRIPT_DIR"

# Colour helpers
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; }

ANSIBLE_OPTS=("${ANSIBLE_EXTRA[@]}")
[[ -n "$DIFF" ]] && ANSIBLE_OPTS+=("$DIFF")

run_ansible() {
    local label="$1" extra_opts="$2"
    echo ""
    echo "━━━ $label ━━━"
    echo "  Playbook : $PLAYBOOK_PATH"
    echo "  Inventory: $INVENTORY_PATH"
    echo "  Options  : ${ANSIBLE_OPTS[*]:-(none)}"
    echo ""
    # shellcheck disable=SC2086
    ansible-playbook "$PLAYBOOK_PATH" -i "$INVENTORY_PATH" \
        --vault-password-file "$VAULT_PASS_PATH" $extra_opts \
        "${ANSIBLE_OPTS[@]}"
}

# ── List tags and exit ────────────────────────────────────────────
if [[ "$LIST_TAGS" == "true" ]]; then
    echo ""
    echo "Available tags:"
    echo ""
    ansible-playbook "$PLAYBOOK_PATH" -i "$INVENTORY_PATH" \
        --vault-password-file "$VAULT_PASS_PATH" --list-tags 2>&1 | \
        grep -oP 'TAGS: \K.*' | tr ',' '\n' | sed 's/^ *//' | sort -u || true
    exit 0
fi

# ── Step 1: Syntax check ───────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   CAPEv2 Ansible Deploy                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo ""
warn "Step 1/3: Syntax check..."
if run_ansible "SYNTAX CHECK" "--syntax-check"; then
    ok "Syntax check passed"
else
    fail "Syntax check failed"
    exit 1
fi

# ── Step 2: Dry-run ────────────────────────────────────────────────
echo ""
warn "Step 2/3: Dry-run (check mode + diff)..."
if run_ansible "DRY-RUN" "--check"; then
    ok "Dry-run completed"
else
    fail "Dry-run reported errors — review above"
    exit 1
fi

# ── Step 3: Execute (unless --check only) ──────────────────────────
if [[ "$CHECK_ONLY" == "true" ]]; then
    echo ""
    ok "--check flag set; skipping execution."
    ok "All checks passed. Ready to deploy."
    exit 0
fi

echo ""
warn "Step 3/3: Execution"
echo ""
echo "━━━ DEPLOY SUMMARY ━━━"
echo "  Playbook  : $PLAYBOOK_PATH"
echo "  Inventory : $INVENTORY_PATH"
echo "  Limit     : ${ANSIBLE_EXTRA[*]:-(none)}"
echo ""
echo -n "Proceed with deployment? [y/N] "
read -r CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Deployment cancelled."
    exit 0
fi

if run_ansible "DEPLOY" ""; then
    ok "Deployment completed successfully"
else
    fail "Deployment failed — review above"
    exit 1
fi
