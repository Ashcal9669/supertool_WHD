# Wireless Hardware Debugger (WHD)
SHELL := /bin/bash
BACKEND := backend
FRONTEND := frontend
PORT ?= 8787
SCENARIO ?= mt7927-pcie-host
HELPER_SOCKET ?= /run/whd/helper.sock

.PHONY: serve-remote setup dev backend-dev frontend-dev demo serve build types check test test-backend test-frontend \
        lint typecheck e2e test-live helper consts fixtures clean

setup:            ## install backend (uv) and frontend (npm) dependencies
	cd $(BACKEND) && uv sync
	cd $(FRONTEND) && npm ci --no-audit --no-fund

consts:           ## regenerate kernel constant modules from the running kernel's headers
	python3 tools/gen_kernel_consts.py

fixtures:         ## rebuild derived/synthetic fixture scenarios from the recorded capture
	cd $(BACKEND) && uv run python tests/fixtures/build_fixtures.py
	cd $(BACKEND) && uv run python tests/fixtures/gen_demo_events.py

types:            ## export OpenAPI and regenerate frontend TypeScript types
	cd $(BACKEND) && uv run whd openapi --out openapi.json
	cd $(FRONTEND) && npx openapi-typescript ../$(BACKEND)/openapi.json -o src/api/schema.d.ts

build: types      ## production frontend build (served by the backend at /)
	cd $(FRONTEND) && npm run build

HOST ?= 127.0.0.1
LOOPBACK := 127.0.0.1 localhost ::1

serve:            ## run WHD on $(HOST):$(PORT) against live hardware (non-loopback HOST enables remote mode)
	cd $(BACKEND) && uv run whd serve --host $(HOST) --port $(PORT) $(if $(filter $(LOOPBACK),$(HOST)),,--allow-remote)

serve-remote:     ## bind to the address your SSH session arrived on; browse http://<that address>:$(PORT) (token required)
	@h=$$(echo "$$SSH_CONNECTION" | awk '{print $$3}'); \
	[ -n "$$h" ] || { echo "not in an SSH session; use: make serve HOST=<this host's address>"; exit 1; }; \
	echo "WHD: http://$$h:$(PORT)  (login with: cd backend && uv run whd token --show)"; \
	cd $(BACKEND) && uv run whd serve --host $$h --port $(PORT) --allow-remote

demo:             ## run WHD in DEMO mode with fixture scenario $(SCENARIO)
	cd $(BACKEND) && uv run whd serve --port $(PORT) --demo $(SCENARIO)

backend-dev:
	cd $(BACKEND) && WHD_DEV_ORIGIN=http://127.0.0.1:5173 uv run uvicorn --factory whd.app:create_app --reload --host 127.0.0.1 --port $(PORT)

frontend-dev:
	cd $(FRONTEND) && WHD_BACKEND=http://127.0.0.1:$(PORT) npm run dev

dev:              ## backend with reload + vite dev server (proxying /api)
	$(MAKE) -j2 backend-dev frontend-dev

lint:
	cd $(BACKEND) && uv run ruff check src tests && uv run ruff format --check src tests
	cd $(FRONTEND) && npx eslint src

typecheck:
	cd $(BACKEND) && uv run mypy
	cd $(FRONTEND) && npx tsc -b

test-backend:
	cd $(BACKEND) && uv run pytest -q

test-frontend:
	cd $(FRONTEND) && npx vitest run

test: test-backend test-frontend

check: lint typecheck test   ## everything CI would run

test-live:        ## read-only smoke tests against this host's real hardware
	cd $(BACKEND) && WHD_LIVE=1 uv run pytest -q -m live

e2e:              ## browser tests (needs a running server: WHD_URL, WHD_TOKEN)
	cd $(FRONTEND) && npx playwright test

helper:           ## run the privileged helper in the foreground (sudo; fixed read-only verbs)
	sudo $(BACKEND)/.venv/bin/python -m whd.helper.server --socket $(HELPER_SOCKET) --allow-uid $$(id -u)

clean:
	rm -rf $(FRONTEND)/dist $(FRONTEND)/e2e-results $(BACKEND)/.pytest_cache $(BACKEND)/.mypy_cache
