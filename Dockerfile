# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

FROM ${PYTHON_IMAGE} AS builder
ENV UV_LINK_MODE=copy UV_NO_PROGRESS=1 UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir uv==0.11.17
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --group build --no-install-project \
    && uv export --quiet --locked --no-dev --no-emit-project --output-file /requirements.txt \
    && uv venv /opt/bounty \
    && uv pip install --python /opt/bounty/bin/python --require-hashes -r /requirements.txt
COPY src ./src
# Precompile once: the runtime root is read-only and never writes bytecode.
RUN uv build --wheel --no-build-isolation \
    && uv pip install --python /opt/bounty/bin/python --no-deps dist/*.whl \
    && /opt/bounty/bin/python -m compileall -q -j 1 /opt/bounty/lib

FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=0.0.0+local
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/CortexLM/bounty" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.cortex.challenge.slug="bounty" \
      io.cortex.challenge.contract="1"
# Security updates published after the base digest was pinned.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 bounty \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin bounty \
    && install -d -o 65532 -g 65532 -m 0700 /data
COPY --from=builder /opt/bounty /opt/bounty
ENV PATH=/opt/bounty/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CHALLENGE_SLUG=bounty \
    CHALLENGE_STATE_DIR=/data
USER 65532:65532
WORKDIR /data
EXPOSE 8000
ENTRYPOINT ["bounty-challenge"]
CMD ["serve"]
