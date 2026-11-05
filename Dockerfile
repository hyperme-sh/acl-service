# syntax=docker/dockerfile:1
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
