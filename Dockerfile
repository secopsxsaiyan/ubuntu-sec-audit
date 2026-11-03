# ubuntu-sec-audit — Docker image with OSCAL tools pre-installed
# Useful for CI/CD pipelines and air-gapped environments where you want
# a consistent, pre-validated toolchain.
#
# Build:  docker build -t ubuntu-sec-audit .
# Run:    docker run --rm --privileged \
#             -v /var/log/audits:/output \
#             ubuntu-sec-audit \
#             --oscal --catalog nist --output-dir /output
#
# NOTE: this image audits the container itself (its packages, configuration
# and services), not the host it runs on; only kernel settings such as sysctl
# values are shared with the host. To audit a host, run the script on it.
# --privileged lets the script read /proc, run sysctl and call auditctl.

FROM ubuntu:24.04

LABEL maintainer="ubuntu-sec-audit"
LABEL description="Ubuntu security audit tool with OSCAL 1.1.2 output support"
LABEL org.opencontainers.image.source="https://github.com/secopsxsaiyan/ubuntu-sec-audit"

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    # Bash + core utilities (already in Ubuntu but be explicit)
    bash \
    coreutils \
    util-linux \
    # Audit tool dependencies (standard mode, zero extra deps)
    sudo \
    procps \
    iproute2 \
    lsb-release \
    apt-utils \
    debsums \
    # Python3 for OSCAL generation
    python3 \
    python3-venv \
    # Optional: AIDE, auditd for check coverage inside container
    aide \
    aide-common \
    auditd \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# OSCAL schema validation (oscal_generate.py --validate). Ubuntu 24.04's
# Python is externally managed (PEP 668), so it goes into a venv; a failed
# install fails the build instead of being silently ignored.
RUN python3 -m venv /opt/oscal-venv \
    && /opt/oscal-venv/bin/pip install --no-cache-dir "compliance-trestle>=2.3.0"
ENV PATH="/opt/oscal-venv/bin:${PATH}"

# Copy tool files
WORKDIR /opt/ubuntu-sec-audit
COPY ubuntu-sec-audit.sh .
COPY lib/ lib/
COPY checks/ checks/
COPY mappings/ mappings/
COPY oscal/ oscal/

RUN chmod +x ubuntu-sec-audit.sh oscal/oscal_generate.py oscal/update_ssp.py

# Default output directory (mount a volume here in production)
RUN mkdir -p /output && chmod 700 /output
ENV AUDIT_REPORT_DIR=/output

ENTRYPOINT ["/opt/ubuntu-sec-audit/ubuntu-sec-audit.sh"]
CMD ["--oscal", "--catalog", "nist", "--output-dir", "/output"]
