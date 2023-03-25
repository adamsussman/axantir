#!/usr/bin/env bash

set -e
set -x

isort -c axantir tests
black --check axantir tests
flake8 axantir tests
mypy -p axantir -p tests
