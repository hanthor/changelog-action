FROM fedora:latest

RUN dnf install -y python3 skopeo git curl && dnf clean all

# Install Cosign
RUN curl -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

COPY changelog.py /changelog.py
RUN chmod +x /changelog.py

ENTRYPOINT ["/changelog.py"]