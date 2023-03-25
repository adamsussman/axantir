#!/usr/bin/env bash

set -e
set -x

isort axantir tests
black axantir tests
flake8 axantir tests
mypy -p axantir -p tests
