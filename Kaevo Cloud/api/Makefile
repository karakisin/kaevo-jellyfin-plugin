.PHONY: build-KaevoV3ConnectorControlFunction \
	build-KaevoConnectorControlTicketFunction \
	build-KaevoConnectorControlSocketFunction \
	build-KaevoConnectorControlNotificationFunction

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

define build_connector_control_push
	cp -R websocket_control "$(ARTIFACTS_DIR)/websocket_control"
	cp -R connector_control "$(ARTIFACTS_DIR)/connector_control"
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
endef

build-KaevoConnectorControlTicketFunction:
	$(build_connector_control_push)

build-KaevoConnectorControlSocketFunction:
	$(build_connector_control_push)

build-KaevoConnectorControlNotificationFunction:
	$(build_connector_control_push)
