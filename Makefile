# Kali MCP Pentest Server - Development Makefile

.PHONY: help install test lint security coverage clean docker-build docker-run

help:
	@echo "Available targets:"
	@echo "  install     - Install dependencies and set up development environment"
	@echo "  test        - Run the full test suite"
	@echo "  test-fast   - Run tests without coverage reporting"
	@echo "  lint        - Run code linting with flake8"
	@echo "  security    - Run security analysis with bandit"
	@echo "  coverage    - Generate test coverage report"
	@echo "  clean       - Clean up test artifacts and cache files"
	@echo "  docker-build- Build the Docker image"
	@echo "  docker-run  - Run the Docker container"

install:
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	./venv/bin/pip install -r requirements-test.txt

test:
	./venv/bin/python -m pytest tests/ -v --cov=main --cov-report=html --cov-report=term-missing --cov-fail-under=85

test-fast:
	./venv/bin/python -m pytest tests/ -v

lint:
	./venv/bin/python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics --exclude=venv
	./venv/bin/python -m flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics --exclude=venv

security:
	./venv/bin/bandit -r . -f json -o bandit-report.json --exclude ./venv
	@if [ -f bandit-report.json ]; then \
		echo "Security report generated: bandit-report.json"; \
		cat bandit-report.json; \
	fi

coverage:
	./venv/bin/python -m pytest tests/ --cov=main --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

clean:
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	rm -rf tests/__pycache__/
	rm -rf htmlcov/
	rm -f .coverage
	rm -f coverage.xml
	rm -f bandit-report.json
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete

docker-build:
	docker build -t kali-mcp-server .

docker-run:
	docker run -p 8080:8080 \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--cap-add=NET_BIND_SERVICE \
		kali-mcp-server

# CI/CD simulation
ci-test: lint security test
	@echo "All CI/CD checks passed!"