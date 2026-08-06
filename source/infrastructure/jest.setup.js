// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Disable aws-cdk-lib's default cfn-lint WASM validator; it adds ~5 min/synth and only emits warnings.
process.env.CDK_VALIDATION = "false";
