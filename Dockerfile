FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libgtk-3-0 \
    libxss1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libx11-xcb1 \
    libxcb1 \
    libxdamage1 \
    libxfixes3 \
    libxext6 \
    libxrender1 \
    libexpat1 \
    libxinerama1 \
    libgl1 \
    libglvnd0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python -m playwright install --with-deps

COPY . .

CMD uvicorn --factory sentinal_fuzz.web.app:create_app --host 0.0.0.0 --port ${PORT:-8080}
