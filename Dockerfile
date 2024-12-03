FROM biocontainers/pandas:1.5.1_cv1

RUN chmod 1777 /tmp
RUN echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free\n\
deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free\n\
deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free\n\
deb http://security.debian.org/debian-security bullseye-security main contrib non-free" > /etc/apt/sources.list
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-dev \
    build-essential \
    ffmpeg libsm6 libxext6 \
    nmap\
    && apt-get clean
RUN pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN mkdir /app
WORKDIR /app
COPY ./src/ /app
RUN test ! -e /app/requirements.txt || pip install --no-cache-dir -r /app/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
ENTRYPOINT ["gunicorn", "app:app", "-b", ":5000", "-k", "gevent", "--log-level", "info"]
