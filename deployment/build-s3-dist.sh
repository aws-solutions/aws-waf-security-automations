#!/bin/bash

# This assumes all of the OS-level configuration has been completed and git repo has already been cloned

# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name
# source-bucket-base-name should be the base name for the S3 bucket location where the template will source the Lambda code from. 
# The template will append '-[region_name]' to this bucket name.
# For example: ./build-s3-dist.sh solutions
# The template will then expect the source code to be located in the solutions-[region_name] bucket

# Check to see if input has been provided:
if [ -z "$1" ]; then
    echo "Please provide the base source bucket name where the lambda code will eventually reside."
    echo "For example: ./build-s3-dist.sh solutions"
    exit 1
fi



# Build source
echo "rm -rf dist"
rm -rf dist
echo "mkdir -p dist"
mkdir -p dist

echo "Staring to build distribution"
echo "------------------------------------------------------------------------------"
echo "Updating Templates"
echo "------------------------------------------------------------------------------"
echo "cp -f aws-waf-security-automations.template dist"
cp -f aws-waf-security-automations.template dist
echo "cp -f aws-waf-security-automations-alb.template dist"
cp -f aws-waf-security-automations-alb.template dist
echo "Updating code source bucket in template with $1"
replace="s/%%BUCKET_NAME%%/$1/g"
echo "sed -i '' -e $replace dist/aws-waf-security-automations.template"
sed -i '' -e $replace dist/aws-waf-security-automations.template
echo "sed -i '' -e $replace dist/aws-waf-security-automations-alb.template"
sed -i '' -e $replace dist/aws-waf-security-automations-alb.template
cd dist
mkdir -p v2
mkdir -p v3
mkdir -p v4
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
zip -q -r9 ../../deployment/dist/v4/custom-resource.zip *