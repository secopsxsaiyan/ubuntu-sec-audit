# shellcheck shell=bash
# Control-mapping cache and OSCAL profile filtering.

# Load control-mapping.json once into memory.
load_control_map() {
# Load control-mapping.json once into memory; queried by report_issue() per finding.
# Avoids spawning a python3 subprocess for every finding (was 37+ forks per run).
_CTRL_MAP_JSON=""
_ctrl_map_file="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"
if [[ -f "$_ctrl_map_file" ]] && command -v python3 >/dev/null 2>&1; then
    _CTRL_MAP_JSON=$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))))" \
        "$_ctrl_map_file" 2>/dev/null || true)
fi
}

# _load_oscal_profile: parse an OSCAL Profile JSON and populate PROFILE_CONTROLS.
# If python3 is unavailable or profile has no include-controls, all checks run.
_load_oscal_profile() {
    local profile_file="$1"
    if ! command -v python3 >/dev/null 2>&1; then
        print_status "WARN" "--profile requires python3; running all checks"
        return
    fi
    mapfile -t PROFILE_CONTROLS < <(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        doc = json.load(f)
    for imp in doc.get('profile',{}).get('imports',[]):
        for sel in imp.get('include-controls',[]):
            for cid in sel.get('with-ids',[]):
                print(cid.lower())
except Exception as e:
    import sys as _s; print(f'profile-load-error: {e}', file=_s.stderr)
" "$profile_file" 2>/dev/null || true)
    local n=${#PROFILE_CONTROLS[@]}
    if [[ $n -gt 0 ]]; then
        print_status "INFO" "OSCAL profile loaded: ${n} control(s) selected — non-matching checks skipped"
    else
        print_status "WARN" "OSCAL profile produced no control IDs — running all checks"
    fi
}

# _check_in_profile: returns 0 (run) or 1 (skip) for a given check function.
# Requires PROFILE_CONTROLS populated and mapping file present.
_check_in_profile() {
    local fn="$1"
    [[ ${#PROFILE_CONTROLS[@]} -eq 0 ]] && return 0   # no filter → always run
    local mapping_file="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"
    [[ ! -f "$mapping_file" ]] && return 0              # no mapping → always run
    command -v python3 >/dev/null 2>&1 || return 0      # no python3 → always run
    local result
    result=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
check_ctrls = set(c.lower() for c in m.get(sys.argv[2],{}).get(sys.argv[3],[]))
profile_set = set(c.lower() for c in sys.argv[4:])
print('yes' if (not check_ctrls) or (check_ctrls & profile_set) else 'no')
" "$mapping_file" "$fn" "$OSCAL_CATALOG" "${PROFILE_CONTROLS[@]}" 2>/dev/null || echo "yes")
    [[ "$result" == "yes" ]]
}
