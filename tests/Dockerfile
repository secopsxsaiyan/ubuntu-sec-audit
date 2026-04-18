FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install baseline packages needed by the audit script
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    sudo \
    bash \
    coreutils \
    procps \
    iproute2 \
    lsb-release \
    openssh-server \
    python3 \
    debsums \
    libpam-modules \
    libpam-runtime \
    rsyslog \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Deliberate misconfigurations for test coverage ──────────────────────────

# SSH: weak settings
RUN mkdir -p /etc/ssh /run/sshd && \
    ssh-keygen -A && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/'          /etc/ssh/sshd_config && \
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*X11Forwarding.*/X11Forwarding yes/'               /etc/ssh/sshd_config && \
    echo '' >> /etc/ssh/sshd_config && \
    echo 'MaxAuthTries 6'        >> /etc/ssh/sshd_config && \
    echo 'LoginGraceTime 120'    >> /etc/ssh/sshd_config

# Remove /etc/issue and /etc/motd (no login banner)
RUN echo "" > /etc/issue && echo "" > /etc/issue.net && echo "" > /etc/motd

# Weak umask: set to 022 in /etc/profile
RUN echo "umask 022" >> /etc/profile

# Create testuser with NOPASSWD sudo (check_users should flag)
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/testuser

# World-readable SSH private key (check_secrets should flag)
RUN mkdir -p /home/testuser/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /home/testuser/.ssh/id_rsa -N "" && \
    chmod 644 /home/testuser/.ssh/id_rsa && \
    chown -R testuser:testuser /home/testuser/.ssh

# .env file with fake secrets (check_secrets should flag)
RUN echo "AWS_SECRET_ACCESS_KEY=fakesecret123" > /root/.env && \
    echo "PASSWORD=hunter2" >> /root/.env && \
    chmod 644 /root/.env

# No unattended-upgrades installed
# (check_unattended will flag absence)

# No auditd rules beyond default (check_auditd will flag if not active/no rules)

# No PAM lockout configured (check_pam_lockout will flag)
# Default Ubuntu 24.04 PAM may have faillock; we ensure it's absent
RUN sed -i '/faillock/d' /etc/pam.d/common-auth 2>/dev/null || true

# No UFW / nftables / iptables rules (check_firewall will flag)
# UFW is not installed by default in this minimal image

# No login banner text
RUN echo "" > /etc/issue && echo "" > /etc/issue.net

# Ensure python3 is available (needed for findings JSONL)
RUN python3 --version

WORKDIR /opt/ubuntu-sec-audit

# Default: drop to bash so run-tests.sh can drive execution
CMD ["/bin/bash"]
