FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y build-essential gcc && \
    apt-get clean

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 10000

ENV FLASK_APP=python.py

CMD ["python", "python.py"]
