FROM python:3.11.7
RUN apt-get update \
    && apt-get install -y \
      cmake \
      liblua5.1-0-dev \
      lua5.1 \
      libjson-c-dev

RUN mkdir /tmp/requirements \
    && git clone git://git.openwrt.org/project/libubox.git /tmp/requirements/libubox \
    && cd /tmp/requirements/libubox \
    && git checkout eb9bcb64185ac155c02cc1a604692c4b00368324 \
    && cmake CMakeLists.txt \
    && make install \
    && git clone git://git.openwrt.org/project/ubus.git /tmp/requirements/ubus \
    && cd /tmp/requirements/ubus \
    && git checkout afa57cce0aff82f4a7a0e509d4387ebc23dd3be7 \
    && cmake CMakeLists.txt \
    && make install \
    && git clone git://git.openwrt.org/project/uci.git /tmp/requirements/uci \
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
