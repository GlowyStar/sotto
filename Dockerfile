FROM python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS build

COPY --from=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable


FROM python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS runtime

RUN groupadd --system --gid 999 relay \
    && useradd --system --uid 999 --gid 999 --no-create-home relay \
    && install --directory --owner relay --group relay --mode 0700 /data

COPY --link --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    RELAY_HOST=0.0.0.0 \
    RELAY_PORT=8765 \
    RELAY_DATABASE=/data/relay.db

USER relay
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=1s \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ['RELAY_PORT'] + '/healthz', timeout=2)"]
CMD ["sotto-relay"]
