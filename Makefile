# Makefile

.PHONY: test run clean install

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

run:
	python3 main.py samples/phishing_test.eml

run-json:
	python3 main.py samples/phishing_test.eml --format json

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete