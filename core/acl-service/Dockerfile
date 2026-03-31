FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY core/events ./core/events
COPY core/models ./core/models
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/auth-service ./core/auth-service
COPY core/acl-service ./core/acl-service
COPY core/tests ./core/tests
RUN uv sync --frozen --no-dev --package acl-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/core/auth-service/src:/app/core/acl-service/src
WORKDIR /app/core/acl-service
CMD ["uv", "run", "--project", "/app/core/acl-service", "python", "-m", "acl_service.main"]
