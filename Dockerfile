FROM fedora:latest

RUN dnf install -y python3 python3-zstandard zstd skopeo git curl && dnf clean all

# Install Cosign
RUN curl -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Install ORAS (for fetching SBOMs stored as OCI referrers via oras attach)
RUN curl -sL "https://api.github.com/repos/oras-project/oras/releases/latest" \
      | python3 -c "import sys,json; v=json.load(sys.stdin)['tag_name'][1:]; print(v)" \
      > /tmp/oras_version && \
    ORAS_VERSION="$(cat /tmp/oras_version)" && \
    curl -L "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/oras.tar.gz && \
    tar -xzf /tmp/oras.tar.gz -C /tmp && \
    mv /tmp/oras /usr/local/bin/oras && \
    chmod +x /usr/local/bin/oras && \
    rm -f /tmp/oras.tar.gz /tmp/oras_version

COPY changelog.py /changelog.py
RUN chmod +x /changelog.py

ENTRYPOINT ["/changelog.py"]
