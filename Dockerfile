FROM python:3.7-alpine

WORKDIR /web-demo
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5012
CMD ["python", "app.py"]