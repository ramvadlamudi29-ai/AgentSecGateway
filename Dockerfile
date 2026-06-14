FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY agentsec_scan ./agentsec_scan
RUN pip install --no-cache-dir .
ENTRYPOINT ["agentsec-scan"]
