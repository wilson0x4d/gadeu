#!/bin/bash
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
source ~/.bashrc
export PS1='\$ '
echo -n -e "\033]0;gadeu\007"
bash --rcfile .venv-bash/bin/activate
