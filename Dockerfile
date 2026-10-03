# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY feint ./feint
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 feint
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[api,viz]" && rm /tmp/*.whl \
    && (pip uninstall -y nvidia-nccl-cu12 nvidia-nccl-cu13 || true) && python -c "import xgboost"
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/feint-adversarial-ids"
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
USER feint
WORKDIR /home/feint
EXPOSE 8000
ENTRYPOINT ["feint"]
CMD ["--help"]
