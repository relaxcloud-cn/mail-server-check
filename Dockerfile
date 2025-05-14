FROM biocontainers/pandas:1.5.1_cv1

RUN chmod 1777 /tmp
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-dev \
    build-essential \
    ffmpeg libsm6 libxext6 \
    nmap\
    && apt-get clean
RUN pip install --upgrade pip
RUN mkdir /app
WORKDIR /app
COPY ./src/ /app
RUN test ! -e /app/requirements.txt || pip install --no-cache-dir -r /app/requirements.txt
ENTRYPOINT ["gunicorn", "app:app", "-b", ":5000", "--log-level", "info"]
