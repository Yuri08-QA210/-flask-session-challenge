FROM python:3.11-slim
WORKDIR /app
RUN pip install flask python-dotenv
COPY . .
RUN mkdir -p logs internal_assets && chmod -R 755 .
EXPOSE 5000
CMD ["python", "app.py"]