#!/bin/bash
# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
set -eo pipefail
sed "s/0.0.0/$SEMVER/g" --in-place pyproject.toml
sed "s/0.0.0/$SEMVER/g" --in-place docs/conf.py
sed "s/0.0.0/$SEMVER/g" --in-place gadeu/__init__.py
sed "s/0abc123/$(git rev-parse --short HEAD)/g" --in-place gadeu/__init__.py
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/
source .venv-bash/bin/activate
python -m build
pip install twine
python -m twine upload --repository $PYPI_REPO dist/*
