FROM fedora:latest

RUN dnf install -y python3 skopeo cosign git && dnf clean all

COPY changelog.py /changelog.py
RUN chmod +x /changelog.py

ENTRYPOINT ["/changelog.py"]
