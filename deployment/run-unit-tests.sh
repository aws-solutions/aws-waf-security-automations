#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./run-unit-tests.sh
#

template_dir="$PWD"
source_dir="$(cd $template_dir/../source; pwd -P)"

echo "Current directory: $template_dir"
echo "Source directory: $source_dir"

run_python_lambda_test() {
	lambda_name=$1
	lambda_description=$2
	echo "------------------------------------------------------------------------------"
	echo "[Test] Python Unit Test: $lambda_description"
	echo "------------------------------------------------------------------------------"

    cd $source_dir/$lambda_name
    echo "run_python_lambda_test: Current directory: $source_dir/$lambda_name"

    # Install dependencies
    echo 'Install Python Testing Dependencies: pip3 install -r ./testing_requirements.txt'
    pip3 install -r ./testing_requirements.txt

    # Set coverage report path
	mkdir -p $source_dir/test/coverage-reports
	coverage_report_path=$source_dir/test/coverage-reports/$lambda_name.coverage.xml
	echo "coverage report path set to $coverage_report_path"

    # Run unit tests with coverage
    python3 -m pytest --cov --cov-report=term-missing --cov-report "xml:$coverage_report_path"
    # The pytest --cov with its parameters and .coveragerc generates a xml cov-report with `coverage/sources` list
    # with absolute path for the source directories. To avoid dependencies of tools (such as SonarQube) on different
    # absolute paths for source directories, this substitution is used to convert each absolute source directory
    # path to the corresponding project relative path. The $source_dir holds the absolute path for source directory.
	sed -i -e "s,<source>$source_dir,<source>source,g" $coverage_report_path
}

# Run Python unit tests
run_python_lambda_test ip_retention_handler "Set IP Retention Lambda"
run_python_lambda_test log_parser "Log Parser"

# Return to the directory where we started
cd $template_dir