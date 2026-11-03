# shellcheck shell=bash
# check_systemd_service_hardening — standard check (sourced by ubuntu-sec-audit.sh)
#
# Only daemons whose child processes are not user sessions or jobs are
# checked. Sandboxing ssh would apply to every login (sudo stops working,
# the filesystem turns read-only), cron would pass it to every job, and
# auditd's ExecStartPost writes /etc/audit/audit.rules, which
# ProtectSystem blocks.

check_systemd_service_hardening() {
    print_status "INFO" "Checking systemd service hardening directives..."
    if ! command -v systemctl >/dev/null 2>&1; then
        append_report "## Systemd Service Hardening\n- ⚪ systemctl not available - not checked"
        _mark_skipped "systemctl not available"
        return 0
    fi
    local -a unhardened=()

    local -a services_to_check=("rsyslog" "fail2ban")
    local -a required_directives=("NoNewPrivileges=yes" "PrivateTmp=yes" "ProtectSystem=")

    local svc directive svc_unit
    for svc in "${services_to_check[@]}"; do
        svc_unit=$(systemctl cat "$svc.service" 2>/dev/null) || continue  # not installed
        local -a missing=()
        for directive in "${required_directives[@]}"; do
            if ! grep -qi "^${directive}" <<< "$svc_unit"; then
                missing+=("$directive")
            fi
        done
        if [[ ${#missing[@]} -gt 0 ]]; then
            unhardened+=("$svc: missing ${missing[*]}")
        fi
    done

    if [[ ${#unhardened[@]} -eq 0 ]]; then
        print_status "OK" "Key systemd services have hardening directives"
        append_report "## Systemd Service Hardening\n- 🟢 NoNewPrivileges/PrivateTmp/ProtectSystem present on checked services"
        return 0
    fi

    local issue_list
    issue_list=$(printf ' - %s\n' "${unhardened[@]}")
    print_status "WARN" "Systemd service hardening gaps: ${#unhardened[@]} service(s)"
    append_report "## Systemd Service Hardening\n- 🟡 ${#unhardened[@]} service(s) lack hardening directives"

    # One drop-in per service. ProtectSystem=full keeps /var writable (logs,
    # fail2ban state). If the service does not come back up with the drop-in,
    # it is removed again and the service restarted without it.
    local svc_fix="" _svc_entry _svc _dropin
    for _svc_entry in "${unhardened[@]}"; do
        _svc="${_svc_entry%%:*}"
        _dropin="/etc/systemd/system/${_svc}.service.d/hardening.conf"
        svc_fix+="sudo /bin/mkdir -p /etc/systemd/system/${_svc}.service.d/"$'\n'
        svc_fix+="sudo /usr/bin/tee ${_dropin} > /dev/null << 'SVCEOF'"$'\n'
        svc_fix+="[Service]"$'\n'
        svc_fix+="NoNewPrivileges=yes"$'\n'
        svc_fix+="PrivateTmp=yes"$'\n'
        svc_fix+="ProtectSystem=full"$'\n'
        svc_fix+="ProtectKernelTunables=yes"$'\n'
        svc_fix+="ProtectControlGroups=yes"$'\n'
        svc_fix+="RestrictRealtime=yes"$'\n'
        svc_fix+="SVCEOF"$'\n'
        svc_fix+="sudo /bin/systemctl daemon-reload"$'\n'
        svc_fix+="sudo /bin/systemctl restart ${_svc}"$'\n'
        svc_fix+="if ! sudo /bin/systemctl is-active --quiet ${_svc}; then"$'\n'
        svc_fix+="    echo '[WARN] ${_svc} did not start with the hardening drop-in - removing it'"$'\n'
        svc_fix+="    sudo /bin/rm -f ${_dropin}"$'\n'
        svc_fix+="    sudo /bin/systemctl daemon-reload"$'\n'
        svc_fix+="    sudo /bin/systemctl restart ${_svc}"$'\n'
        svc_fix+="fi"$'\n'
    done
    svc_fix+="# Verify:
sudo /bin/systemctl show rsyslog fail2ban 2>/dev/null | grep -E 'NoNewPrivileges|PrivateTmp|ProtectSystem'"

    report_issue 4 \
        "Systemd services missing hardening directives" \
        "${#unhardened[@]} service(s) lack NoNewPrivileges/PrivateTmp/ProtectSystem - increases blast radius of service compromise" \
        "${svc_fix}" \
        0 \
        "Services without hardening:\n${issue_list}"
}
