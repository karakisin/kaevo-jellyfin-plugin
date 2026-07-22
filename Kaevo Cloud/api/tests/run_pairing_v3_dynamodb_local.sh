#!/bin/sh
set -eu

container="kaevo-pairing-v3-dynamodb-local-$$"
cleanup() { docker stop "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker run --rm -d --name "$container" -p 127.0.0.1::8000 \
  amazon/dynamodb-local:latest -jar DynamoDBLocal.jar -inMemory -sharedDb >/dev/null
port="$(docker port "$container" 8000/tcp | sed 's/.*://')"
endpoint="http://127.0.0.1:$port"

attempt=0
until AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-west-2 \
  uv run --with 'boto3>=1.34,<2' python -c "import boto3; boto3.client('dynamodb', endpoint_url='$endpoint').list_tables()" >/dev/null 2>&1
do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 31 ] || { echo "DynamoDB Local did not become ready" >&2; exit 1; }
  sleep 1
done

AWS_EC2_METADATA_DISABLED=true AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-west-2 \
KAEVO_DYNAMODB_LOCAL_ENDPOINT="$endpoint" \
uv run --with 'boto3>=1.34,<2' --with 'cryptography>=48,<49' --with 'PyJWT[crypto]>=2.9,<3' --with pytest \
  python -m pytest api/tests/test_pairing_v3_dynamodb_local.py api/tests/test_v3_connector_control_dynamodb_local.py -q
