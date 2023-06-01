#!/bin/bash

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

#
# The container assumes the source code is mounted inside /root
#
podman run --rm -t -v .:/root:Z ghcr.io/nethserver/python3-nethsec-test
