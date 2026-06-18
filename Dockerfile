# Aegis gateway — container image for public deployment (Render/Fly/Railway).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGIS_GATEWAY_HOST=0.0.0.0

WORKDIR /app
RUN pip install --no-cache-dir uv

# Install the package (non-editable) + runtime deps from pyproject.
COPY pyproject.toml README.md policy.yaml ./
COPY src ./src
COPY evals ./evals
RUN uv pip install --system --no-cache .

# Bake the eval metrics into the image so the deployed dashboard shows real results.
RUN aegis-eval || true

EXPOSE 8000
# Render/Fly inject $PORT; default to 8000 locally. Factory so the app builds at boot.
CMD ["sh", "-c", "uvicorn aegis.gateway.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
