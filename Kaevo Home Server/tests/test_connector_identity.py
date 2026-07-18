import os

import jwt

from kaevo_home_server.connector_identity import ConnectorIdentity


def test_connector_private_key_is_persistent_and_owner_only(tmp_path):
    path = tmp_path / "identity" / "connector.pem"
    first = ConnectorIdentity.load_or_create(path)
    second = ConnectorIdentity.load_or_create(path)
    assert first.thumbprint == second.thumbprint
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert "PRIVATE" not in str(first.public_jwk)


def test_connector_proof_is_es256_dpop_bound_to_request(tmp_path):
    identity = ConnectorIdentity.load_or_create(tmp_path / "connector.pem")
    proof = identity.proof("POST", "https://cloud.example/v1/home-connectors/c-1/heartbeat", now=1_000)
    header = jwt.get_unverified_header(proof)
    claims = jwt.decode(proof, jwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"], options={"verify_aud": False})
    assert header["typ"] == "dpop+jwt"
    assert claims["htm"] == "POST"
    assert claims["htu"].endswith("/heartbeat")
