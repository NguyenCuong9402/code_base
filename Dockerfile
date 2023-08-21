# syntax = docker/dockerfile:experimental
FROM python:3.7
RUN apt-get update && \
    apt-get install -y locales && \
    sed -i -e 's/# vi_VN UTF-8/vi_VN UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y default-mysql-client
RUN apt-get install -y gnupg
# Add a /source-code-base volume
VOLUME ["/source-code-base"]
WORKDIR /source-code-base
ADD . /source-code-base
RUN pip install -r requirements.txt
EXPOSE 5012
CMD gunicorn --workers=3 --threads=1 --timeout=3600 --preload -b 0.0.0.0:5012 server:app