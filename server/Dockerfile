FROM python:3.11-slim
WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt
COPY pyproject.toml README.md ./
COPY agentsec_scan ./agentsec_scan
COPY server ./server
RUN mkdir -p /app/data/reports
ENV AUDIT_DATA_DIR=/app/data
ENV AGENTSEC_REPORTS_DIR=/app/data/reports
EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
