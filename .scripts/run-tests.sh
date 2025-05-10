#!/bin/bash
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
set -eo pipefail
missingVenv=false
if [ -z "$VIRTUAL_ENV" ]; then
    source .venv-bash/bin/activate
    missingVenv=true
fi
python -m punit --verbose --trait '!integration' --trait '!hardcoded' --trait '!longrunning' --trait '!manual' #--report html --output results.html
if $missingVenv; then
    deactivate
fi
