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
# NOTE: --privileged is required because the script reads /proc, runs sysctl,
# and calls auditctl. For read-only CI checks you can drop to --cap-add SYS_PTRACE.

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
    python3-pip \
    # Optional: AIDE, auditd for check coverage inside container
    aide \
    aide-common \
    auditd \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install optional OSCAL validation library
RUN pip3 install --no-cache-dir compliance-trestle 2>/dev/null || true

# Copy tool files
WORKDIR /opt/ubuntu-sec-audit
COPY ubuntu-sec-audit.sh .
COPY mappings/ mappings/
COPY oscal/ oscal/

RUN chmod +x ubuntu-sec-audit.sh oscal/oscal_generate.py oscal/update_ssp.py

# Default output directory (mount a volume here in production)
RUN mkdir -p /output && chmod 700 /output
ENV AUDIT_REPORT_DIR=/output

ENTRYPOINT ["/opt/ubuntu-sec-audit/ubuntu-sec-audit.sh"]
CMD ["--oscal", "--catalog", "nist", "--output-dir", "/output"]
