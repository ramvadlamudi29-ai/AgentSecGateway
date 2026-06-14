FROM python:3.11-slim
WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt
COPY server ./server
COPY .github ./.github
RUN mkdir -p /app/data
ENV AUDIT_DATA_DIR=/app/data
EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
