#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./run-unit-tests.sh
#

template_dir="$PWD"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Test] Build Athena Queries"
echo "------------------------------------------------------------------------------"
echo 'pip3 install -r ../tests/testing_requirements.txt'
pip3 install -r ../source/tests/testing_requirements.txt
echo 'pytest -s ../tests'
pytest -s ../source/tests
