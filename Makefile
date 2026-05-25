PYTHON ?= python
SMOKE_DIR ?= .pcr-smoke

.PHONY: verify smoke clean

verify:
	$(PYTHON) -m py_compile src/personal_context_router/*.py
	$(PYTHON) -m pytest -q
	$(PYTHON) -m personal_context_router.cli --help >/dev/null
	$(MAKE) smoke

smoke:
	rm -rf "$(SMOKE_DIR)"
	$(PYTHON) -m personal_context_router.cli run-sample --workdir "$(SMOKE_DIR)"

clean:
	rm -rf "$(SMOKE_DIR)" .pytest_cache build dist *.egg-info src/*.egg-info
