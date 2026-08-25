.PHONY: build-KaevoV3ConnectorControlFunction

build-KaevoV3ConnectorControlFunction:
	cp connector_control/connector_control_handler.py "$(ARTIFACTS_DIR)/connector_control_handler.py"
	cp src/pairing_v3.py "$(ARTIFACTS_DIR)/pairing_v3.py"
	python3 -m pip install \
		--requirement connector_control/requirements.txt \
		--target "$(ARTIFACTS_DIR)" \
		--platform manylinux_2_34_aarch64 \
		--platform manylinux2014_aarch64 \
		--implementation cp \
		--python-version 3.12 \
		--only-binary=:all:
	python3 connector_control/verify_linux_arm64_artifact.py "$(ARTIFACTS_DIR)"
