#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./run-unit-tests.sh
#

# Get reference for all important folders
template_dir="$PWD"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist and node_modules folders"
echo "------------------------------------------------------------------------------"
echo "find $source_dir -iname \"node_modules\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "node_modules" -type d -exec rm -r "{}" \; 2> /dev/null

echo "find $source_dir -iname \"dist\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "dist" -type d -exec rm -r "{}" \; 2> /dev/null

echo "find ../ -type f -name 'package-lock.json' -delete"
find "$source_dir" -type f -name 'package-lock.json' -delete

echo "------------------------------------------------------------------------------"
echo "[Test] Reputation Lists Parser"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/reputation-lists-parser || exit 1
npm install
npm test

echo "pwd: current directory"
pwd

echo "------------------------------------------------------------------------------"
echo "[Test] Build Athena Queries"
echo "------------------------------------------------------------------------------"
echo 'pip3 install -r ../tests/testing_requirements.txt'
pip3 install -r ../tests/testing_requirements.txt
echo 'pytest -s ../tests'
pytest -s ../tests