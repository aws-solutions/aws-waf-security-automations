#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name version-code
#
# Paramenters:
#  - source-bucket-base-name: Name for the S3 bucket location where the template will source the Lambda
#    code from. The template will append '-[region_name]' to this bucket name.
#    For example: ./build-s3-dist.sh solutions v2.2
#    The template will then expect the source code to be located in the solutions-[region_name] bucket
#
#  - version-code: version of the package

# Check to see if input has been provided:
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Please provide the base source bucket name and version where the lambda code will eventually reside."
    echo "For example: ./build-s3-dist.sh solutions v2.2"
    exit 1
fi

# Get reference for all important folders
template_dir="$PWD"
dist_dir="$template_dir/dist"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist and node_modules folders"
echo "------------------------------------------------------------------------------"
echo "rm -rf $dist_dir"
rm -rf "$dist_dir"
echo "find $source_dir -iname \"node_modules\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "node_modules" -type d -exec rm -r "{}" \; 2> /dev/null
echo "find $source_dir -iname \"dist\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "dist" -type d -exec rm -r "{}" \; 2> /dev/null
echo "find ../ -type f -name 'package-lock.json' -delete"
find "$source_dir" -type f -name 'package-lock.json' -delete
echo "find ../ -type f -name '.DS_Store' -delete"
find "$source_dir" -type f -name '.DS_Store' -delete
echo "mkdir -p $dist_dir"
mkdir -p "$dist_dir"

echo "------------------------------------------------------------------------------"
echo "[Packing] Templates"
echo "------------------------------------------------------------------------------"
echo "cp -f $template_dir/aws-waf-security-automations.template dist"
cp -f "$template_dir/aws-waf-security-automations.template" "$dist_dir"
echo "cp -f $template_dir/aws-waf-security-automations-cloudfront.template dist"
cp -f "$template_dir/aws-waf-security-automations-cloudfront.template" "$dist_dir"
echo "cp -f $template_dir/aws-waf-security-automations-alb.template dist"
cp -f "$template_dir/aws-waf-security-automations-alb.template" "$dist_dir"

echo "Updating code source bucket in template with $1"
replace="s/%%BUCKET_NAME%%/$1/g"
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations.template
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations-cloudfront.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations-cloudfront.template
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations-alb.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations-alb.template

echo "Updating code source version in template with $2"
replace="s/%%VERSION%%/$2/g"
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations.template
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations-cloudfront.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations-cloudfront.template
echo "sed -i '' -e $replace $dist_dir/aws-waf-security-automations-alb.template"
sed -i '' -e "$replace" "$dist_dir"/aws-waf-security-automations-alb.template

echo "------------------------------------------------------------------------------"
echo "[Packing] Log Parser"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/log-parser || exit 1
zip -q -r9 "$dist_dir"/log-parser.zip ./*

echo "------------------------------------------------------------------------------"
echo "[Packing] Access Handler"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/access-handler || exit 1
zip -q -r9 "$dist_dir"/access-handler.zip ./*

echo "------------------------------------------------------------------------------"
echo "[Packing] IP Lists Parser"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/reputation-lists-parser || exit 1
npm install --production
zip -q -r9 "$dist_dir"/reputation-lists-parser.zip ./*
zip -d "$dist_dir"/reputation-lists-parser.zip '*.spec.js' '*_test.js'

echo "------------------------------------------------------------------------------"
echo "[Packing] Custom Resource"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/custom-resource || exit 1
zip -q -r9 "$dist_dir"/custom-resource.zip ./*
