test:
	@echo "Generating and Running Tests - Please Be Patient"
	@echo "------------------------------------------------"
	mocha

test-nyan:
	@echo "Generating and Running Tests - Please Be Patient"
	@echo "------------------------------------------------"
	mocha --reporter nyan

.PHONY: test
