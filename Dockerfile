FROM python:3.8
VOLUME ["/code-base"]
WORKDIR /code-base
ADD . /code-base
COPY . /code-base/
RUN pip install -r requirements.txt
EXPOSE 5012
CMD gunicorn --workers=3 --threads=1 --timeout=3600 --preload -b 0.0.0.0:5012 server:app