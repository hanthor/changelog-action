FROM fedora:latest

RUN dnf install -y python3 python3-zstandard zstd skopeo git curl && dnf clean all

# Install Cosign
RUN curl -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Install ORAS (for fetching SBOMs stored as OCI referrers via oras attach)
RUN curl -L "https://github.com/oras-project/oras/releases/latest/download/oras_linux_amd64.tar.gz" | \
    tar -xz -C /usr/local/bin oras && \
    chmod +x /usr/local/bin/oras

COPY changelog.py /changelog.py
RUN chmod +x /changelog.py

ENTRYPOINT ["/changelog.py"]
