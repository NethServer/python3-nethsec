FROM python:3.13.9
RUN apt-get update \
    && apt-get install -y \
    cmake \
    liblua5.1-0-dev \
    lua5.1 \
    libjson-c-dev

ADD https://github.com/openwrt/libubox.git#815633847cd32ffe6da28943cbeb37edc88265c8 /tmp/requirements/libubox
RUN cd /tmp/requirements/libubox \
    && cmake CMakeLists.txt \
    && make install
ADD https://github.com/openwrt/ubus.git#3cc98db1a422dcf560f2d6347fd410f17565a89d /tmp/requirements/ubus
RUN cd /tmp/requirements/ubus \
    && cmake CMakeLists.txt \
    && make install
ADD https://github.com/openwrt/uci.git#66127cd76c5d0bd46d5a90302cc6110f53a4e2f8 /tmp/requirements/uci
RUN cd /tmp/requirements/uci \
    && cmake CMakeLists.txt \
    && make install
RUN rm -rf /tmp/requirements \
    && echo "/usr/local/lib" >> /etc/ld.so.conf.d/local.conf \
    && ldconfig

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt
WORKDIR /app
CMD ["python3", "-m", "pytest"]
