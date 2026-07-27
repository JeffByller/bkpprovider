FROM python:3.11-slim

# Install iputils-ping and tzdata for timezone configuration
ENV TZ=America/Recife
RUN apt-get update && apt-get install -y iputils-ping tzdata && \
    ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

CMD ["python", "main.py"]
