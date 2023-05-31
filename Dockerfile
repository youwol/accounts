FROM python:3.9-slim


RUN apt-get update \
    && apt-get install -y \
        ca-certificates brotli\
    && apt-get autoremove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8080
WORKDIR /root

COPY /py-youwol/requirements-docker.txt /root/
RUN pip3 install --no-cache-dir --upgrade -r "requirements-docker.txt"

COPY /py-youwol/src/youwol/utils /root/youwol/utils
COPY /py-youwol/src/youwol/backends/accounts /root/youwol/backends/accounts
COPY /src /root/


ENTRYPOINT ["python3.9", "-u", "main.py", "prod"]
