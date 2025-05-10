#!/bin/bash
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
set -eo pipefail
if [[ "$PYTHON_VERSION" != "" ]]; then
    PYPATH=`which python$PYTHON_VERSION`
else
    PYPATH="python3"
fi
$PYPATH -m venv --prompt "gadeu" .venv-bash
source .venv-bash/bin/activate
pip install pip-tools
pip-compile -o requirements.txt --all-extras --strip-extras pyproject.toml > /dev/null
pip install -r requirements.txt
rm requirements.txt
rm -rf gadeu.egg-info
deactivate
