FROM python:3.11.7
RUN apt-get update \
    && apt-get install -y \
      cmake \
      liblua5.1-0-dev \
      lua5.1 \
      libjson-c-dev

RUN mkdir /tmp/requirements \
    && git clone https://github.com/openwrt/libubox.git /tmp/requirements/libubox \
    && cd /tmp/requirements/libubox \
    && git checkout 49056d178f42da98048a5d4c23f83a6f6bc6dd80 \
    && cmake CMakeLists.txt \
    && make install \
    && git clone https://github.com/openwrt/ubus.git /tmp/requirements/ubus \
    && cd /tmp/requirements/ubus \
    && git checkout 60e04048a0e2f3e33651c19e62861b41be4c290f \
    && cmake CMakeLists.txt \
    && make install \
    && git clone https://github.com/openwrt/uci.git /tmp/requirements/uci \
    && cd /tmp/requirements/uci \
    && git checkout 16ff0badbde7e17ec3bd1f827ffe45922956cf86 \
    && cmake CMakeLists.txt \
    && make install \
    && rm -rf /tmp/requirements \
    && echo "/usr/local/lib" >> /etc/ld.so.conf.d/local.conf \
    && ldconfig

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt
WORKDIR /app
CMD ["python3", "-m", "pytest"]
