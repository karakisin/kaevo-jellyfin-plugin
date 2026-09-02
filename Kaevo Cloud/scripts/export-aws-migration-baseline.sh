#!/usr/bin/env bash
set -euo pipefail

# Export rollback-relevant AWS configuration without exporting application data,
# credential values, secret values, Lambda environment values, or CloudFront
# custom-header values. Account identifiers are redacted from the generated files.

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_directory=$1
region=${AWS_REGION:-us-west-2}
snapshot_tmp=$(mktemp -d "${TMPDIR:-/tmp}/kaevo-aws-baseline.XXXXXX")
trap 'rm -rf -- "$snapshot_tmp"' EXIT

mkdir -p "$output_directory"

redact_file() {
  local source_file=$1
  local destination_file=$2
  sed -E \
    -e 's/[0-9]{12}/[ACCOUNT_ID]/g' \
    -e 's/(AKIA|ASIA)[A-Z0-9]{16}/[REDACTED_AWS_ACCESS_KEY_ID]/g' \
    "$source_file" >"$destination_file"
}

capture_json() {
  local destination_file=$1
  shift
  local raw_file="$snapshot_tmp/raw.json"
  "$@" --output json >"$raw_file"
  redact_file "$raw_file" "$output_directory/$destination_file"
}

aws --region "$region" cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE IMPORT_COMPLETE \
  --query 'StackSummaries[].{StackName:StackName,StackId:StackId,Status:StackStatus,Created:CreationTime,Updated:LastUpdatedTime}' \
  --output json >"$snapshot_tmp/stacks.json"
redact_file "$snapshot_tmp/stacks.json" "$output_directory/cloudformation-stacks.json"

aws --region "$region" cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE IMPORT_COMPLETE \
  --query 'StackSummaries[].StackName' --output text | tr '\t' '\n' | while IFS= read -r stack_name; do
  [[ -n "$stack_name" ]] || continue
  safe_stack_name=${stack_name//[^A-Za-z0-9_.-]/_}
  aws --region "$region" cloudformation describe-stacks --stack-name "$stack_name" --output json |
    jq '{Stacks:[.Stacks[] | {
      StackName,
      StackId,
      CreationTime,
      LastUpdatedTime,
      StackStatus,
      Parameters:[.Parameters[]? | if (.ParameterKey | test("(?i)(secret|token|password|credential|key)")) then .ParameterValue="[REDACTED]" else . end],
      Outputs:[.Outputs[]? | if (.OutputKey | test("(?i)(secret|token|password|credential|key)")) then .OutputValue="[REDACTED]" else . end],
      Tags
    }]}' >"$snapshot_tmp/stack.json"
  redact_file "$snapshot_tmp/stack.json" "$output_directory/cloudformation-$safe_stack_name.json"
done

capture_json cloudfront-distributions.json \
  aws --region us-east-1 cloudfront list-distributions \
  --query 'DistributionList.Items[].{Id:Id,ARN:ARN,DomainName:DomainName,Status:Status,Enabled:Enabled,Comment:Comment,Origins:Origins.Items[].{Id:Id,DomainName:DomainName,OriginPath:OriginPath,CustomOriginConfig:CustomOriginConfig}}'

aws --region us-east-1 cloudfront list-distributions --query 'DistributionList.Items[].Id' --output text | tr '\t' '\n' | while IFS= read -r distribution_id; do
  [[ -n "$distribution_id" ]] || continue
  aws --region us-east-1 cloudfront get-distribution-config --id "$distribution_id" --output json |
    jq 'walk(if type == "object" and has("HeaderValue") then .HeaderValue="[REDACTED]" else . end)' \
      >"$snapshot_tmp/cloudfront.json"
  redact_file "$snapshot_tmp/cloudfront.json" "$output_directory/cloudfront-$distribution_id.json"
done

capture_json load-balancers.json \
  aws --region "$region" elbv2 describe-load-balancers
capture_json target-groups.json \
  aws --region "$region" elbv2 describe-target-groups

aws --region "$region" elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text | tr '\t' '\n' | while IFS= read -r load_balancer_arn; do
  [[ -n "$load_balancer_arn" ]] || continue
  safe_name=$(sed -E 's#^.*/##; s#[^A-Za-z0-9_.-]#_#g' <<<"$load_balancer_arn")
  capture_json "listeners-$safe_name.json" \
    aws --region "$region" elbv2 describe-listeners --load-balancer-arn "$load_balancer_arn"
done

capture_json ecs-clusters.json \
  aws --region "$region" ecs list-clusters

aws --region "$region" ecs list-clusters --query 'clusterArns[]' --output text | tr '\t' '\n' | while IFS= read -r cluster_arn; do
  [[ -n "$cluster_arn" ]] || continue
  safe_cluster=$(sed -E 's#^.*/##; s#[^A-Za-z0-9_.-]#_#g' <<<"$cluster_arn")
  capture_json "ecs-cluster-$safe_cluster.json" \
    aws --region "$region" ecs describe-clusters --clusters "$cluster_arn" --include SETTINGS
  capture_json "ecs-services-$safe_cluster.json" \
    aws --region "$region" ecs list-services --cluster "$cluster_arn"
  aws --region "$region" ecs list-services --cluster "$cluster_arn" --query 'serviceArns[]' --output text | tr '\t' '\n' | while IFS= read -r service_arn; do
    [[ -n "$service_arn" ]] || continue
    safe_service=$(sed -E 's#^.*/##; s#[^A-Za-z0-9_.-]#_#g' <<<"$service_arn")
    capture_json "ecs-service-$safe_service.json" \
      aws --region "$region" ecs describe-services --cluster "$cluster_arn" --services "$service_arn"
  done
done

aws --region "$region" ecs list-task-definitions --family-prefix kaevo --status ACTIVE --query 'taskDefinitionArns[]' --output text | tr '\t' '\n' | while IFS= read -r task_definition_arn; do
  [[ -n "$task_definition_arn" ]] || continue
  safe_task_definition=$(sed -E 's#^.*/##; s#[^A-Za-z0-9_.-]#_#g' <<<"$task_definition_arn")
  aws --region "$region" ecs describe-task-definition --task-definition "$task_definition_arn" --output json |
    jq '.taskDefinition.containerDefinitions |= map(
      .environment = [(.environment[]? | {name:.name,value:"[REDACTED]"})]
      | .secrets = [(.secrets[]? | {name:.name,valueFrom:.valueFrom})]
    )' >"$snapshot_tmp/task-definition.json"
  redact_file "$snapshot_tmp/task-definition.json" "$output_directory/ecs-task-definition-$safe_task_definition.json"
done

capture_json ecr-repositories.json \
  aws --region "$region" ecr describe-repositories
aws --region "$region" ecr describe-repositories --query 'repositories[].repositoryName' --output text | tr '\t' '\n' | while IFS= read -r repository_name; do
  [[ -n "$repository_name" ]] || continue
  safe_repository=${repository_name//\//_}
  capture_json "ecr-images-$safe_repository.json" \
    aws --region "$region" ecr describe-images --repository-name "$repository_name"
done

aws --region "$region" lambda list-functions --output json |
  jq '{Functions:[.Functions[] | {
    FunctionName,FunctionArn,Runtime,Architectures,Handler,CodeSize,Description,Timeout,MemorySize,
    LastModified,CodeSha256,Version,RevisionId,PackageType,Layers,
    EnvironmentVariableNames:(.Environment.Variables // {} | keys),
    KMSKeyArn,VpcConfig,DeadLetterConfig,TracingConfig,EphemeralStorage
  }]}' >"$snapshot_tmp/lambda.json"
redact_file "$snapshot_tmp/lambda.json" "$output_directory/lambda-functions.json"

capture_json api-gateway-http-apis.json \
  aws --region "$region" apigatewayv2 get-apis

aws --region "$region" apigatewayv2 get-apis --query 'Items[].ApiId' --output text | tr '\t' '\n' | while IFS= read -r api_id; do
  [[ -n "$api_id" ]] || continue
  capture_json "api-gateway-$api_id-routes.json" \
    aws --region "$region" apigatewayv2 get-routes --api-id "$api_id"
  capture_json "api-gateway-$api_id-stages.json" \
    aws --region "$region" apigatewayv2 get-stages --api-id "$api_id"
done

capture_json dynamodb-tables.json \
  aws --region "$region" dynamodb list-tables
aws --region "$region" dynamodb list-tables --query 'TableNames[]' --output text | tr '\t' '\n' | while IFS= read -r table_name; do
  [[ -n "$table_name" ]] || continue
  safe_table=${table_name//[^A-Za-z0-9_.-]/_}
  capture_json "dynamodb-$safe_table.json" \
    aws --region "$region" dynamodb describe-table --table-name "$table_name"
done

capture_json secrets-metadata.json \
  aws --region "$region" secretsmanager list-secrets \
  --query 'SecretList[].{ARN:ARN,Name:Name,Description:Description,LastChangedDate:LastChangedDate,LastAccessedDate:LastAccessedDate,RotationEnabled:RotationEnabled,RotationRules:RotationRules,Tags:Tags}'

capture_json lightsail-container-services.json \
  aws --region "$region" lightsail get-container-services

printf 'Created redacted AWS migration baseline at %s\n' "$output_directory"
