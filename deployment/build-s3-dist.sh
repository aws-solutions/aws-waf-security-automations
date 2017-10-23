#!/bin/bash

# This assumes all of the OS-level configuration has been completed and git repo has already been cloned

# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh 
# Then upload the zipped files to source-bucket-base-name, the base name for the S3 bucket location where the template will source the Lambda code from. 
# The template will append '-[region_name]' to this bucket name.
# When loading the template file, enter then name of this bucke as BucketName.
# The template will then expect the source code to be located in the solutions-[region_name] bucket
# Load the template files directly from the deployment directory (no new templates are generate).
#
# Build source
echo "rm -rf dist"
rm -rf dist
echo "mkdir -p dist"
mkdir -p dist
cd dist

echo "Staring to build distribution"
echo "------------------------------------------------------------------------------"
mkdir -p v2
mkdir -p v3
echo "------------------------------------------------------------------------------"
echo "[Packing] Log Parser"
echo "------------------------------------------------------------------------------"
cd ../../source/log-parser
zip -q -r9 ../../deployment/dist/v2/log-parser.zip *
echo ""
echo "------------------------------------------------------------------------------"
echo "[Packing] Access Handler"
echo "------------------------------------------------------------------------------"
cd ../access-handler
zip -q -r9 ../../deployment/dist/v2/access-handler.zip *
echo ""
echo "------------------------------------------------------------------------------"
echo "[Packing] IP Lists Parser"
echo "------------------------------------------------------------------------------"
cd ../reputation-lists-parser
zip -q -r9 ../../deployment/dist/v3/reputation-lists-parser.zip *
echo ""
echo "------------------------------------------------------------------------------"
echo "[Packing] Custom Resource"
echo "------------------------------------------------------------------------------"
cd ../custom-resource
zip -q -r9 ../../deployment/dist/v3/custom-resource.zip *
echo "------------------------------------------------------------------------------"
echo "[Done] "
echo "------------------------------------------------------------------------------"
