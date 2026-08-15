# syntax=docker/dockerfile:1
FROM python:3.13-alpine

RUN pip install --no-cache-dir "boto3==1.42.0" "psycopg[binary]==3.3.1"

WORKDIR /proofs
COPY run.py schema.sql ./

ENTRYPOINT ["python", "-u", "run.py"]
