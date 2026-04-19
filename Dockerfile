FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ARG OPTIX_API_URL=https://optixthreatintelligence.co.uk
ENV OPTIX_API_URL=${OPTIX_API_URL}
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8090

EXPOSE 8090

CMD ["python", "main.py"]
