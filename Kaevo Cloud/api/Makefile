.PHONY: build-KaevoV3ConnectorControlFunction

build-KaevoV3ConnectorControlFunction:
	cp connector_control/connector_control_handler.py "$(ARTIFACTS_DIR)/connector_control_handler.py"
	cp src/pairing_v3.py "$(ARTIFACTS_DIR)/pairing_v3.py"
	python3 -m pip install --requirement connector_control/requirements.txt --target "$(ARTIFACTS_DIR)"
