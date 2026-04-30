default: check

install:
    uv sync --all-extras

check: lint typecheck test

lint:
    uv run ruff check .
    uv run ruff format --check .

fmt:
    uv run ruff check --fix .
    uv run ruff format .

typecheck:
    uv run mypy src/

test:
    uv run pytest

test-cov:
    uv run pytest --cov=src/guard --cov-report=term-missing
