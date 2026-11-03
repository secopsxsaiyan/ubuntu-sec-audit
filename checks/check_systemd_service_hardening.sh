# shellcheck shell=bash
# check_systemd_service_hardening — standard check (sourced by ubuntu-sec-audit.sh)

check_systemd_service_hardening() {
    print_status "INFO" "Checking systemd service hardening directives..."
    local -a unhardened=()

    local -a services_to_check=("ssh" "sshd" "cron" "rsyslog" "auditd" "fail2ban")
    local -a required_directives=("NoNewPrivileges=yes" "PrivateTmp=yes" "ProtectSystem=")

    for svc in "${services_to_check[@]}"; do
        systemctl cat "$svc.service" >/dev/null 2>&1 || continue  # skip if not installed
        local svc_unit
        svc_unit=$(systemctl cat "$svc.service" 2>/dev/null || true)
        local missing=()
        for directive in "${required_directives[@]}"; do
            if ! grep -qi "$directive" <<< "$svc_unit"; then
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
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${unhardened[@]}")
        print_status "WARN" "Systemd service hardening gaps: ${#unhardened[@]} service(s)"
        append_report "## Systemd Service Hardening\n- 🟡 ${#unhardened[@]} service(s) lack hardening directives"

        # Build per-service drop-in commands for each unhardened service
        local svc_fix=""
        local _restarts=""
        for _svc_entry in "${unhardened[@]}"; do
            local _svc="${_svc_entry%%:*}"
            # rsyslog/auditd/cron write to /var; use ProtectSystem=full not strict
            local _protect_system="strict"
            case "$_svc" in
                rsyslog|auditd|cron) _protect_system="full" ;;
            esac
            svc_fix+="sudo /bin/mkdir -p /etc/systemd/system/${_svc}.service.d/"$'\n'
            svc_fix+="sudo /usr/bin/tee /etc/systemd/system/${_svc}.service.d/hardening.conf > /dev/null << 'SVCEOF'"$'\n'
            svc_fix+="[Service]"$'\n'
            svc_fix+="NoNewPrivileges=yes"$'\n'
            svc_fix+="PrivateTmp=yes"$'\n'
            svc_fix+="ProtectSystem=${_protect_system}"$'\n'
            svc_fix+="PrivateDevices=yes"$'\n'
            svc_fix+="ProtectKernelTunables=yes"$'\n'
            svc_fix+="ProtectKernelModules=yes"$'\n'
            svc_fix+="ProtectControlGroups=yes"$'\n'
            svc_fix+="RestrictRealtime=yes"$'\n'
            svc_fix+="SVCEOF"$'\n'
            _restarts+="sudo /bin/systemctl restart ${_svc} 2>/dev/null || true"$'\n'
        done
        svc_fix+="sudo /bin/systemctl daemon-reload"$'\n'
        svc_fix+="${_restarts}"
        svc_fix+="# Verify:
sudo /bin/systemctl show ssh cron rsyslog auditd fail2ban 2>/dev/null | grep -E 'NoNewPrivileges|PrivateTmp|ProtectSystem'"

        report_issue 4 \
            "Systemd services missing hardening directives" \
            "${#unhardened[@]} service(s) lack NoNewPrivileges/PrivateTmp/ProtectSystem - increases blast radius of service compromise" \
            "${svc_fix}" \
            0 \
            "Services without hardening:\n${issue_list}"
    fi
}
