PYTHON ?= python
SMOKE_DIR ?= .pcr-smoke
PCR_PYTHONPATH := src$(if $(PYTHONPATH),:$(PYTHONPATH))

.PHONY: verify smoke clean

verify:
	$(PYTHON) -m py_compile src/personal_context_router/*.py
	PYTHONPATH="$(PCR_PYTHONPATH)" $(PYTHON) -m pytest -q
	PYTHONPATH="$(PCR_PYTHONPATH)" $(PYTHON) -m personal_context_router.cli --help >/dev/null
	$(MAKE) smoke

smoke:
	rm -rf "$(SMOKE_DIR)"
	PYTHONPATH="$(PCR_PYTHONPATH)" $(PYTHON) -m personal_context_router.cli run-sample --workdir "$(SMOKE_DIR)"
	PYTHONPATH="$(PCR_PYTHONPATH)" $(PYTHON) -m personal_context_router.cli doctor "$(SMOKE_DIR)" --out "$(SMOKE_DIR)/doctor.md"

clean:
	rm -rf "$(SMOKE_DIR)" .pytest_cache build dist *.egg-info src/*.egg-info
