# web — 대시보드 백엔드. dahv2/air(pymavlink 포함) + FastAPI/uvicorn.
FROM dahv2/air:latest
RUN pip3 install --no-cache-dir fastapi "uvicorn[standard]"
WORKDIR /app
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
