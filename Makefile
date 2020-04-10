TEMPLATE_OUTPUT_BUCKET=aws-waf-security-automations-eu-west-1-365919415693
DIST_OUTPUT_BUCKET=aws-waf-security-automations-eu-west-1-365919415693
APP_ACCESS_LOG_BUCKET?=access-logs-eu-west-1-365919415693
SOLUTION_NAME="telemetry"
VERSION=1
AWS_REGION=eu-west-1
PROFILE?=Telemetry-$(ENVIRONMENT)
APPLICATION_STACK_NAME?=WAFAutomations

all: build upload

build:
	cd deployment ; \
	./build-s3-dist.sh $(TEMPLATE_OUTPUT_BUCKET) $(DIST_OUTPUT_BUCKET) $(SOLUTION_NAME) $(VERSION)

upload:
	$(eval ENVIRONMENT := $(shell bash -c 'read -p "ENVIRONMENT [dev, test, prod]: " var; echo $$var'))
	aws s3 sync deployment/functions s3://$(DIST_OUTPUT_BUCKET)/functions --include "*.zip" --profile $(PROFILE)
	aws s3 sync deployment/templates s3://$(TEMPLATE_OUTPUT_BUCKET)/templates --include "*.yml" --profile $(PROFILE)

cloudformation:
	$(eval ENVIRONMENT := $(shell bash -c 'read -p "ENVIRONMENT [dev, test, prod]: " var; echo $$var'))
	-@unset AWS_DEFAULT_REGION; \
	aws cloudformation create-stack \
		--profile $(PROFILE) \
		--stack-name $(APPLICATION_STACK_NAME) \
		--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
		--template-body file://cloudformation.yml \
		--parameters ParameterKey=AppAccessLogBucket,ParameterValue=$(APP_ACCESS_LOG_BUCKET) \
		--output text