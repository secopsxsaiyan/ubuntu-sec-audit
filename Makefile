.PHONY: test lint unit python integration

test: lint unit python

lint:
	tests/lint.sh

unit:
	bats tests/unit

python:
	python3 -m unittest discover -s tests/python

integration:
	bash tests/run-tests.sh
