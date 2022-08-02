#!/bin/bash

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

#
# Create ghcr.io/nethserver/python3-next-test container
#

set -e

repobase="ghcr.io/nethserver"

images=()
container=$(buildah from docker.io/ubuntu:jammy)

trap "buildah rm ${container}" EXIT

echo "Disalble IPv6 for APT"
buildah run ${container} /bin/bash -c "echo 'Acquire::ForceIPv4 \"true\";' > /etc/apt/apt.conf.d/99force-ipv4"

echo "Installing build depencies..."
buildah run ${container} /bin/bash -c "apt-get update"
buildah run ${container} /bin/bash -c "apt install software-properties-common -y && add-apt-repository ppa:deadsnakes/ppa -y && apt-get install python3.10 -y"
buildah run ${container} /bin/bash -c "apt-get update && apt-get -y install --no-install-recommends \
    lua5.1 liblua5.1-0-dev libjson-c-dev ca-certificates git cmake make pkg-config gcc"

echo "Compile libubox"
buildah run ${container} /bin/bash -c "git clone git://git.openwrt.org/project/libubox.git ~/libubox && \
  cd ~/libubox && \
  cmake CMakeLists.txt && \
  make install && \
  cd .. && \
  rm -rf libubox"

echo "Compile uci"
buildah run ${container} /bin/bash -c "git clone git://git.openwrt.org/project/uci.git ~/uci && \
  cd ~/uci && \
  cmake cmake CMakeLists.txt && \
  make install && \
  cd .. && \
  rm -rf uci"

echo "Install packages needed for PyUci"
buildah run ${container} /bin/bash -c "apt-get -y install --no-install-recommends \
    python3-dev python3-setuptools python3-pip python3-pytest \
    python3-pytest-cov lcov python3-venv \
    && \
    apt-get clean"

echo "Preparing venv"
buildah config --workingdir /root ${container}
buildah run ${container} /bin/bash -c "python3 -m venv venv && source venv/bin/activate && python3 -m pip install pyuci pytest"

echo "Setup image"
buildah add ${container} entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["python3", "-m", "pytest"]' ${container}
buildah commit ${container} "${repobase}/python3-nextsec-test"
images+=("${repobase}/python3-nextsec-test")

if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "::set-output name=images::%s\n" "${images[*]}"
else
    printf "Publish the images with:\n\n"
    for image in "${images[@]}"; do printf "  buildah push %s docker://%s:latest\n" "${image}" "${image}" ; done
    printf "\n"
fi
