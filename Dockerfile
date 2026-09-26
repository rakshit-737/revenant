# REVENANT — slim, non-root image.
# Build:  docker build -t revenant .
# Serve:  docker run --rm -p 8000:8000 -v "$PWD/tests/fixtures:/evidence:ro" \
#           -e REVENANT_EVIDENCE_ROOT=/evidence revenant serve --host 0.0.0.0 --port 8000
# CLI:    docker run --rm -v "$PWD:/data" revenant analyze /data/evidence.jsonl
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="REVENANT" \
      org.opencontainers.image.description="Evidence-graph forensic timeline reconstruction with confidence grading (lab-only DFIR)." \
      org.opencontainers.image.source="https://github.com/rakshit-737/revenant" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 REVENANT_EVIDENCE_ROOT=/evidence
RUN useradd --create-home --uid 10001 revenant && mkdir -p /evidence && chown revenant /evidence
COPY --from=build /dist/*.whl /tmp/
RUN wheel="$(ls /tmp/*.whl)" && pip install --no-cache-dir "${wheel}[api,evtx]" && rm -f /tmp/*.whl
USER revenant
WORKDIR /home/revenant
EXPOSE 8000
ENTRYPOINT ["revenant"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
