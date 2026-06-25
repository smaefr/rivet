.PHONY: test run

test:
	python3 -m pytest --cov=src/rivet --cov-report=term-missing --cov-fail-under=80

run:
	python3 -m rivet detect
	python3 -m rivet pcr
