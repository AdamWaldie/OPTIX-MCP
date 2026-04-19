FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ARG OPTIX_API_URL=https://optixthreatintelligence.co.uk
ENV OPTIX_API_URL=${OPTIX_API_URL}
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8090

ARG OPTIX_SKIP_AUTH=false
ENV OPTIX_SKIP_AUTH=${OPTIX_SKIP_AUTH}

EXPOSE 8090

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8090/health || exit 1

CMD ["python", "main.py"]
