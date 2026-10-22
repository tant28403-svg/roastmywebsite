.PHONY: install test lint format docker-build

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

format:
	ruff format src tests

docker-build:
	docker build -t roastmywebsite .