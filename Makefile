# Convenience targets for the AI SOC pipeline (Linux/macOS/WSL).
# On Windows PowerShell, run the equivalent commands from README.md instead.
PYTHON ?= .venv/bin/python
PIP    ?= .venv/bin/pip

.DEFAULT_GOAL := help

.PHONY: help setup lint test simulate alerts triage report iocs evaluate navigator clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

setup: ## Create the virtualenv and install dependencies
	python -m venv .venv
	$(PIP) install -r requirements.txt

lint: ## Run ruff
	$(PYTHON) -m ruff check .

test: ## Run the test suite
	$(PYTHON) -m pytest -q

simulate: ## Generate synthetic Cowrie logs and ground truth
	$(PYTHON) -m honeypot.simulate_attacks

alerts: ## Run the detections locally over the simulated log
	$(PYTHON) -m detections.local_rules data/raw/cowrie_simulated.json -o data/processed/alerts.jsonl

triage: ## Run the triage agent over the simulated log
	$(PYTHON) -m triage.triage_agent --events data/raw/cowrie_simulated.json

report: ## Render the analyst queue as HTML
	$(PYTHON) -m triage.report

iocs: ## Export IOCs to CSV + STIX 2.1
	$(PYTHON) -m triage.iocs --events data/raw/cowrie_simulated.json

evaluate: ## Score the LLM against the rule-only baseline
	$(PYTHON) -m evaluation.evaluate

navigator: ## Regenerate the ATT&CK Navigator coverage layer
	$(PYTHON) -m detections.navigator

clean: ## Remove generated artifacts and caches
	rm -rf .pytest_cache .ruff_cache
	rm -f data/processed/* evaluation/results/*
