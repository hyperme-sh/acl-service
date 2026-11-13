# syntax=docker/dockerfile:1
FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d AS verifier
WORKDIR /opt/acl-admission
COPY admission/package.json admission/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY admission/history_admission.py admission/verify.mjs admission/store-operation.mjs admission/statement_source.py admission/statement-graph.mjs ./

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
COPY --from=build /build/.venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --create-home acl \
    && python -I -c "import acl_service.app; from pathlib import Path; import acl_service; assert str(Path(acl_service.__file__).resolve()).startswith('/opt/venv/')"
WORKDIR /home/acl
USER 10001:10001
EXPOSE 8000
CMD ["python", "-I", "-m", "acl_service.main"]
