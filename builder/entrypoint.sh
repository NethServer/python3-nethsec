#!/bin/bash

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Activate python virtual env, if present
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi

exec "$@"
