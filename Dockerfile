FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Optional Go-based tools are installed if available in the build context.
# Users can also mount prebuilt binaries.

WORKDIR /app
COPY . /app

RUN python -m pip install --no-cache-dir -e ".[dev]"

ENTRYPOINT ["roastmywebsite"]
CMD ["--help"]