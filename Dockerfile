# syntax=docker/dockerfile:1
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS epoch-verifier
WORKDIR /source
COPY admission/sociacl-native.rev /tmp/sociacl-native.rev
RUN revision=$(cat /tmp/sociacl-native.rev) \
    && echo "$revision" | grep -Eq '^[0-9a-f]{40}$' \
    && git init . \
    && git fetch --depth=1 https://github.com/FyberLabs/SociACL.git "$revision" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$revision" \
    && cargo build --release -p sociacl-c --locked

FROM python:3.13-slim-bookworm AS epoch-contract
ENV PYTHONDONTWRITEBYTECODE=1
COPY --from=epoch-verifier /source/target/release/libsociacl.so /opt/acl-admission/libsociacl.so
COPY src/acl_service/infrastructure/epoch_verifier.py admission/test_epoch_native.py admission/epoch-fixture.json /checks/
WORKDIR /checks
CMD ["python", "-m", "unittest", "-v", "test_epoch_native"]

FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d AS verifier
WORKDIR /opt/acl-admission
COPY admission/package.json admission/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY admission/history_admission.py admission/verify.mjs admission/store-operation.mjs admission/statement_source.py admission/statement-graph.mjs admission/statement-quota.mjs admission/delegation_source.py admission/delegation-graph.mjs ./

FROM python:3.13-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY scripts/install-image-runtime.py /tmp/install-image-runtime.py
# The token is mounted only for dependency installation, never copied into a layer.
RUN --mount=type=secret,id=dependency_read_token,required=true \
    python /tmp/install-image-runtime.py

FROM python:3.13-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier /usr/local/bin/node /usr/local/bin/node
RUN node --version
COPY --from=verifier /opt/acl-admission /opt/acl-admission
COPY --from=epoch-verifier /source/target/release/libsociacl.so /opt/acl-admission/libsociacl.so
COPY --from=build /build/.venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --create-home acl \
    && python -I -c "import acl_service.app; from pathlib import Path; import acl_service; assert str(Path(acl_service.__file__).resolve()).startswith('/opt/venv/')" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import EpochStatusVerifier; assert not EpochStatusVerifier().matches_status(b'{}', b'{}', now_ms=0, skew_ms=0, policy_max_age_ms=0)" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import EpochManifestVerifier; assert not EpochManifestVerifier().matches_manifest(b'{}', b'{}')"
WORKDIR /home/acl
USER 10001:10001
EXPOSE 8000
CMD ["python", "-I", "-m", "acl_service.main"]
