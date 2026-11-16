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
# Preserve legal texts from dependencies already fetched for this native build.
RUN mkdir -p /native-notices/cargo /native-notices/owner \
    && find /usr/local/cargo/registry/src -type f \( -iname '*license*' -o -iname '*licence*' -o -iname '*notice*' -o -iname 'copying*' \) -exec cp --parents '{}' /native-notices/cargo/ \; \
    && find /source -maxdepth 2 -type f \( -iname '*license*' -o -iname '*notice*' -o -iname 'copying*' \) -exec cp --parents '{}' /native-notices/owner/ \; \
    && cp Cargo.lock /native-notices/Cargo.lock \
    && test -n "$(find /native-notices/owner -type f -print -quit)"


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
COPY scripts/prepare_node_notices.mjs /tmp/prepare_node_notices.mjs
COPY notices/npm /tmp/npm-notices
RUN node /tmp/prepare_node_notices.mjs node_modules npm-notices.json /tmp/npm-notices
COPY admission/signed_store_source.py admission/credential_source.py admission/credential-graph.mjs admission/device_transfer_source.py admission/device-transfer.mjs admission/history_admission.py admission/contact_source.py admission/contact-document.mjs admission/first_media_owner.py admission/verify.mjs admission/group-authority.mjs admission/store-operation.mjs admission/statement_source.py admission/statement-graph.mjs admission/app-object-policy.mjs admission/statement-quota.mjs admission/delegation_source.py admission/delegation-graph.mjs admission/media_source.py admission/group_source.py admission/group_membership.py admission/group_key_source.py admission/group_wrap_source.py admission/group_item_source.py admission/group_owner_wrap_source.py admission/group_item_grants.py ./

FROM python:3.13-slim-bookworm AS media-contract
RUN pip install --no-cache-dir cryptography==50.0.2
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier /usr/local/bin/node /usr/local/bin/node
COPY --from=verifier /opt/acl-admission /opt/acl-admission
COPY --from=epoch-verifier /source/target/release/libsociacl.so /opt/acl-admission/libsociacl.so
COPY src /checks/src
COPY admission/test_media_native.py admission/media-native-fixture.json /checks/
ENV PYTHONPATH=/checks/src:/opt/acl-admission
WORKDIR /checks
CMD ["python3", "-m", "unittest", "-v", "test_media_native"]

FROM python:3.13-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
COPY scripts/install-image-runtime.py /tmp/install-image-runtime.py
# Frozen runtime dependencies are installed without private credentials.
RUN python /tmp/install-image-runtime.py
COPY scripts/prepare_notices.py /tmp/prepare_notices.py
COPY .github/workflows/third-party-notices /tmp/notice-supplements
RUN /build/.venv/bin/python /tmp/prepare_notices.py /notices/python /tmp/notice-supplements

FROM python:3.13-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier /usr/local/bin/node /usr/local/bin/node
RUN node --version
COPY --from=verifier /opt/acl-admission /opt/acl-admission
COPY --from=epoch-verifier /source/target/release/libsociacl.so /opt/acl-admission/libsociacl.so
COPY --from=build /build/.venv /opt/venv
COPY --from=build /notices /usr/share/acl-service/notices
COPY --from=epoch-verifier /native-notices /usr/share/acl-service/notices/native
COPY LICENSE NOTICE /usr/share/acl-service/
COPY notices/node /usr/share/acl-service/notices/node
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --create-home acl \
    && python -I -c "import acl_service.app; from pathlib import Path; import acl_service; assert str(Path(acl_service.__file__).resolve()).startswith('/opt/venv/')" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import EpochStatusVerifier; assert not EpochStatusVerifier().matches_status(b'{}', b'{}', now_ms=0, skew_ms=0, policy_max_age_ms=0)" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import EpochManifestVerifier; assert not EpochManifestVerifier().matches_manifest(b'{}', b'{}')" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import SettledEpochVerifier; assert not SettledEpochVerifier().matches_settled(b'{}')" \
    && python -I -c "from acl_service.infrastructure.epoch_verifier import PrivateGrantVerifier; assert not PrivateGrantVerifier().matches_grant(b'{}', b'{}')" \
    && python -I -c "from acl_service.infrastructure.group_epoch_verifier import GroupEpochVerifier; v=GroupEpochVerifier(); assert not v.matches_manifest(b'{}', b'{}'); assert not v.verifies_history(b'{}'); assert not v.matches_settled(b'{}')"
RUN --mount=type=bind,source=scripts/review_runtime_legal.py,target=/tmp/review_runtime_legal.py,readonly \
    python -I /tmp/review_runtime_legal.py > /usr/share/acl-service/notices/runtime-review.json
WORKDIR /home/acl
USER 10001:10001
EXPOSE 8000
CMD ["python", "-I", "-m", "acl_service.main"]
