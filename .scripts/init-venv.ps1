#!/bin/pwsh
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
$ErrorActionPreference = "Stop"
if ($env:PYTHON_VERSION -ne "") {
    $PYPATH=$(Get-Command "python$env:PYTHON_VERSION").Source
} else {
    $PYPATH=$(Get-Command "python3").Source
}
& $PYPATH -m venv --prompt "gadeu" .venv-pwsh
. .\.venv-pwsh\Scripts\Activate.ps1
& pip install pip-tools
& pip-compile -o requirements.txt --all-extras --strip-extras pyproject.toml
& pip install -r requirements.txt
rm requirements.txt
rm -R -Force gadeu.egg-info
deactivate
