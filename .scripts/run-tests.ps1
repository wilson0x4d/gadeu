#!/bin/pwsh
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
$missingVenv = $null -eq $env:VIRTUAL_ENV
if ($true -eq $missingVenv) {
    & .\.venv-pwsh\Scripts\Activate.ps1
}
python -m punit --verbose --trait '!integration' --trait '!hardcoded' --trait '!longrunning' --trait '!manual'
if ($true -eq $missingVenv) {
    deactivate
}
