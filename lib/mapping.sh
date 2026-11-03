# shellcheck shell=bash
# Control-mapping cache and OSCAL profile filtering.

# load_control_map: read CONTROL_MAP_FILE once into CTRL_MAP so lookups need
# no subprocess. Keys are "check_id|framework", values "ID1,ID2". Without
# python3 or the file, the map stays empty and findings carry no control IDs.
load_control_map() {
    CTRL_MAP=()
    [[ -f "$CONTROL_MAP_FILE" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    local _check _fw _ids
    while IFS=$'\t' read -r _check _fw _ids; do
        [[ -n "$_check" && -n "$_ids" ]] && CTRL_MAP["${_check}|${_fw}"]="$_ids"
    done < <(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
for check, entry in m.items():
    if not isinstance(entry, dict):
        continue
    for fw, ids in entry.items():
        if isinstance(ids, list) and ids:
            print(check + "\t" + fw + "\t" + ",".join(ids))
' "$CONTROL_MAP_FILE" 2>/dev/null || true)
}

# _ctrl_ids_for CHECK_ID — "fw:ids|fw:ids" for every selected framework.
_ctrl_ids_for() {
    local check_id="$1" fw ids out=""
    for fw in "${FRAMEWORKS[@]}"; do
        ids="${CTRL_MAP["${check_id}|${fw}"]:-}"
        [[ -n "$ids" ]] && out+="${out:+|}${fw}:${ids}"
    done
    printf '%s' "$out"
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
# Checks without controls in the selected catalog always run.
_check_in_profile() {
    local fn="$1"
    [[ ${#PROFILE_CONTROLS[@]} -eq 0 ]] && return 0   # no filter → always run
    local ids="${CTRL_MAP["${fn}|${OSCAL_CATALOG}"]:-}"
    [[ -z "$ids" ]] && return 0                         # unmapped → always run
    local id want
    for id in ${ids//,/ }; do
        for want in "${PROFILE_CONTROLS[@]}"; do
            [[ "${id,,}" == "${want,,}" ]] && return 0
        done
    done
    return 1
}
