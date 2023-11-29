FROM python:3.8

WORKDIR /app

# Copy mã nguồn của ứng dụng vào thư mục /app
COPY . /app

# Cài đặt các dependencies
RUN pip install -r requirements.txt

# Mở cổng cần thiết
EXPOSE 5012

# Chạy ứng dụng khi container được khởi chạy
CMD ["python", "server.py"]
#CMD gunicorn --workers=3 --threads=1 --timeout=3600 --preload -b 0.0.0.0:5012 server:app