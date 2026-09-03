#!/usr/bin/env bash
set -euo pipefail

OUTPUT_PATH="${1:-/tmp/kaevo-physical-validation-evidence.txt}"
MODE="${2:-snapshot}"
REGION="us-west-2"
CONTROL_STACK="kaevo-cloud-dev-connector-control"
API_STACK="kaevo-cloud-dev"
PRODUCTION_API_STACK="kaevo-cloud-production"
RELAY_STACK="kaevo-playback-relay-green"
LEGACY_RELAY_STACK="kaevo-playback-relay-beta"
RELAY_SERVICE="kaevo-playback-relay-green"

mkdir -p "$(dirname "$OUTPUT_PATH")"
exec 3>"$OUTPUT_PATH"

record() {
  printf '%s=%s\n' "$1" "$2" >&3
  printf '%s=%s\n' "$1" "$2"
}

stack_status() {
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query 'Stacks[0].StackStatus' --output text
}

stack_output() {
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue | [0]" --output text
}

metric_sum() {
  local namespace="$1"
  local metric="$2"
  local region="$3"
  shift 3
  aws cloudwatch get-metric-statistics \
    --region "$region" \
    --namespace "$namespace" \
    --metric-name "$metric" \
    --dimensions "$@" \
    --start-time "$METRIC_START" \
    --end-time "$METRIC_END" \
    --period 60 \
    --statistics Sum \
    --output json | jq -r '[.Datapoints[].Sum] | add // 0'
}

assert_safe_log_file() {
  local path="$1"
  python3 - "$path" <<'PY'
import json
import re
import sys

messages = json.load(open(sys.argv[1], encoding="utf-8"))
patterns = {
    "authorization_header": re.compile(r"authorization[\"' :=]+(?:bearer|basic)\s+", re.I),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "credential_field": re.compile(r"(?:aws_secret_access_key|secretaccesskey|sessiontoken)[\"' :=]+[^\s,}]+", re.I),
    "playback_url": re.compile(r"https?://\S+/v1/playback/", re.I),
    "secret_field": re.compile(r"(?:connection_ticket|relay_ticket|playback_grant|origin_auth_secret)[\"' :=]+[^\s,}]+", re.I),
}
matches = {name: sum(bool(pattern.search(str(message))) for message in messages) for name, pattern in patterns.items()}
if any(matches.values()):
    print(json.dumps(matches, sort_keys=True))
    raise SystemExit(1)
print("0")
PY
}

export AWS_PAGER=""
caller_arn=$(aws sts get-caller-identity --region "$REGION" --query Arn --output text)
[[ "$caller_arn" == */KaevoDeploymentRole/* ]]
record credential_type temporary_oidc_sts

control_status=$(stack_status "$CONTROL_STACK")
relay_status=$(stack_status "$RELAY_STACK")
legacy_status=$(stack_status "$LEGACY_RELAY_STACK")
[[ "$control_status" == "CREATE_COMPLETE" || "$control_status" == "UPDATE_COMPLETE" ]]
[[ "$relay_status" == "CREATE_COMPLETE" || "$relay_status" == "UPDATE_COMPLETE" ]]
[[ "$legacy_status" == "CREATE_COMPLETE" || "$legacy_status" == "UPDATE_COMPLETE" ]]
record control_stack_status "$control_status"
record green_relay_stack_status "$relay_status"
record legacy_relay_stack_status "$legacy_status"

relay_url=$(stack_output "$RELAY_STACK" RelayPublicUrl)
service_url=$(stack_output "$RELAY_STACK" ServiceUrl)
distribution_id=$(stack_output "$RELAY_STACK" DistributionId)
websocket_url=$(stack_output "$CONTROL_STACK" WebSocketUrl)
api_url=$(stack_output "$API_STACK" ApiUrl)
http_api_id=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).hostname.split(".")[0])' "$api_url")
websocket_api_id=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).hostname.split(".")[0])' "$websocket_url")
for secret_value in "$relay_url" "$service_url" "$distribution_id" "$websocket_url" "$api_url" "$http_api_id" "$websocket_api_id"; do
  echo "::add-mask::${secret_value}"
done

service_state=$(aws lightsail get-container-services --region "$REGION" --service-name "$RELAY_SERVICE" \
  --query 'containerServices[0].currentDeployment.state' --output text)
service_power=$(aws lightsail get-container-services --region "$REGION" --service-name "$RELAY_SERVICE" \
  --query 'containerServices[0].power' --output text)
service_scale=$(aws lightsail get-container-services --region "$REGION" --service-name "$RELAY_SERVICE" \
  --query 'containerServices[0].scale' --output text)
record green_relay_deployment_state "$service_state"
record green_relay_power "$service_power"
record green_relay_scale "$service_scale"
[[ "$service_state" == "ACTIVE" && "$service_power" == "nano" && "$service_scale" == "1" ]]

direct_health=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${service_url%/}/health")
direct_protected=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${service_url%/}/v1/playback/not-a-grant/Videos/not-an-item/stream")
edge_health=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${relay_url%/}/health")
edge_invalid_grant=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${relay_url%/}/v1/playback/not-a-grant/Videos/not-an-item/stream")
record direct_health_status "$direct_health"
record direct_protected_status "$direct_protected"
record cloudfront_health_status "$edge_health"
record cloudfront_invalid_grant_status "$edge_invalid_grant"
[[ "$direct_health" == "200" && "$direct_protected" == "403" && "$edge_health" == "200" && "$edge_invalid_grant" == "401" ]]

origin_protocol=$(aws cloudfront get-distribution-config --id "$distribution_id" \
  --query 'DistributionConfig.Origins.Items[0].CustomOriginConfig.OriginProtocolPolicy' --output text)
origin_tls=$(aws cloudfront get-distribution-config --id "$distribution_id" \
  --query 'DistributionConfig.Origins.Items[0].CustomOriginConfig.OriginSslProtocols.Items[0]' --output text)
viewer_protocol=$(aws cloudfront get-distribution-config --id "$distribution_id" \
  --query 'DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy' --output text)
[[ "$origin_protocol" == "https-only" && "$origin_tls" == "TLSv1.2" && "$viewer_protocol" == "redirect-to-https" ]]
record cloudfront_origin_protocol "$origin_protocol"
record cloudfront_origin_tls "$origin_tls"
record cloudfront_viewer_protocol "$viewer_protocol"

containers=$(aws lightsail get-container-services --region "$REGION" --service-name "$RELAY_SERVICE" \
  --query 'containerServices[0].currentDeployment.containers' --output json)
container_env_keys=$(jq -r '.[].environment | keys[]' <<<"$containers" | sort -u)
[[ "$container_env_keys" == $'KAEVO_ORIGIN_AUTH_SECRET\nPLAYBACK_GRANT_SIGNING_KEY' ]]
[[ -z "$(grep -E '^AWS_|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN' <<<"$container_env_keys" || true)" ]]
record relay_permanent_aws_credentials 0
record relay_runtime_secret_names 2

dev_function_matches=0
while IFS= read -r function_name; do
  [[ -z "$function_name" ]] && continue
  configuration=$(aws lambda get-function-configuration --region "$REGION" --function-name "$function_name" --output json)
  if ! jq -e '(.Environment.Variables // {}) | has("PLAYBACK_RELAY_PUBLIC_URL")' <<<"$configuration" >/dev/null; then
    continue
  fi
  dev_relay=$(aws lambda get-function-configuration --region "$REGION" --function-name "$function_name" \
    --query 'Environment.Variables.PLAYBACK_RELAY_PUBLIC_URL' --output text)
  echo "::add-mask::${dev_relay}"
  [[ "$dev_relay" == "$relay_url" ]]
  dev_function_matches=$((dev_function_matches + 1))
done < <(aws cloudformation list-stack-resources --region "$REGION" --stack-name "$API_STACK" \
  --query "StackResourceSummaries[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId" \
  --output text | tr '\t' '\n')
[[ "$dev_function_matches" -ge 2 ]]
production_relay=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$PRODUCTION_API_STACK" \
  --query "Stacks[0].Parameters[?ParameterKey=='PlaybackRelayPublicUrl'].ParameterValue | [0]" --output text)
echo "::add-mask::${production_relay}"
[[ "$production_relay" != "$relay_url" ]]
record development_playback_target green_lightsail
record development_functions_verified "$dev_function_matches"
record production_playback_target unchanged_legacy

route_settings=$(aws apigatewayv2 get-stage --region "$REGION" --api-id "$http_api_id" --stage-name dev \
  --query 'RouteSettings' --output json)
for route in \
  'POST /v3/remote-requests/claim' \
  'POST /v3/home-connectors/{connectorId}/control-ticket' \
  'POST /v3/remote-requests/{requestId}/claim'; do
  jq -e --arg route "$route" '.[$route].DetailedMetricsEnabled == true' <<<"$route_settings" >/dev/null
done
ws_logging=$(aws apigatewayv2 get-stage --region "$REGION" --api-id "$websocket_api_id" --stage-name dev --output json)
jq -e '.DefaultRouteSettings.DetailedMetricsEnabled == true' <<<"$ws_logging" >/dev/null
jq -e '.AccessLogSettings.Format | contains("$context.routeKey") and contains("$context.status") and (contains("authorization") | not)' <<<"$ws_logging" >/dev/null
record structured_control_logging active_redacted
record detailed_route_metrics active

root_keys=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)
root_mfa=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
[[ "$root_keys" == "0" && "$root_mfa" == "1" ]]
record root_access_keys "$root_keys"
record root_mfa_enabled "$root_mfa"

security_template_path=/tmp/kaevo-security-baseline-original.yaml
aws cloudformation get-template --region "$REGION" --stack-name kaevo-security-baseline \
  --template-stage Original --query TemplateBody --output text >"$security_template_path"
temporary_delete_permission_count=$(grep -Ec \
  'iam:(PutRolePolicy|DeleteRolePolicy|CreatePolicyVersion|DeletePolicyVersion)' \
  "$security_template_path" || true)
[[ "$temporary_delete_permission_count" == "0" ]]
record temporary_bootstrap_delete_permissions "$temporary_delete_permission_count"

METRIC_END=$(date -u -d '90 seconds ago' '+%Y-%m-%dT%H:%M:%SZ')
METRIC_START=$(date -u -d '990 seconds ago' '+%Y-%m-%dT%H:%M:%SZ')
record metric_window_start "$METRIC_START"
record metric_window_end "$METRIC_END"
record http_legacy_collection_claim_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$http_api_id" Name=Stage,Value=dev Name=Route,Value='POST /v3/remote-requests/claim')"
record http_exact_claim_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$http_api_id" Name=Stage,Value=dev Name=Route,Value='POST /v3/remote-requests/{requestId}/claim')"
record http_control_ticket_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$http_api_id" Name=Stage,Value=dev Name=Route,Value='POST /v3/home-connectors/{connectorId}/control-ticket')"
record websocket_connect_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev Name=Route,Value='$connect')"
record websocket_disconnect_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev Name=Route,Value='$disconnect')"
record websocket_ping_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev Name=Route,Value=ping)"
record websocket_recover_count "$(metric_sum AWS/ApiGateway Count "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev Name=Route,Value=recover)"
record websocket_4xx_count "$(metric_sum AWS/ApiGateway 4XXError "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev)"
record websocket_5xx_count "$(metric_sum AWS/ApiGateway 5XXError "$REGION" Name=ApiId,Value="$websocket_api_id" Name=Stage,Value=dev)"
record cloudfront_request_count "$(metric_sum AWS/CloudFront Requests us-east-1 Name=DistributionId,Value="$distribution_id" Name=Region,Value=Global)"
record cloudfront_bytes_downloaded "$(metric_sum AWS/CloudFront BytesDownloaded us-east-1 Name=DistributionId,Value="$distribution_id" Name=Region,Value=Global)"

start_ms=$(python3 -c 'import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()*1000))' "$METRIC_START")
log_files=()
while IFS= read -r group; do
  [[ -z "$group" ]] && continue
  path="/tmp/kaevo-log-scan-$(printf '%s' "$group" | sha256sum | cut -c1-12).json"
  aws logs filter-log-events --region "$REGION" --log-group-name "$group" --start-time "$start_ms" \
    --query 'events[].message' --output json >"$path"
  log_files+=("$path")
done < <(aws logs describe-log-groups --region "$REGION" \
  --query "logGroups[?contains(logGroupName, 'kaevo-cloud-dev-connector-control') || contains(logGroupName, 'kaevo-cloud-dev-v3-connector-control')].logGroupName" \
  --output text | tr '\t' '\n')
relay_log_file=/tmp/kaevo-relay-log-scan.json
aws lightsail get-container-log --region "$REGION" --service-name "$RELAY_SERVICE" --container-name relay \
  --query 'logEvents[].message' --output json >"$relay_log_file" || printf '[]\n' >"$relay_log_file"
log_files+=("$relay_log_file")
leak_count=0
for path in "${log_files[@]}"; do
  result=$(assert_safe_log_file "$path") || leak_count=$((leak_count + 1))
  [[ "$result" == "0" ]] || leak_count=$((leak_count + 1))
done
[[ "$leak_count" == "0" ]]
record sensitive_log_matches "$leak_count"
record evidence_mode "$MODE"
record evidence_generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

exec 3>&-
