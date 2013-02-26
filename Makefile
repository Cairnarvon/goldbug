all:
	@echo "Targets:"
	@echo "  pypi        Build distributions and upload them to PyPI."
	@echo "  doczip      Build docs and zip them for manual upload to PyPI."
	@echo "  tests       Run the unit tests."
	@echo "  clean       Clear out temporary cruft."

.PHONY: pypi
pypi:
	python setup.py sdist upload

.PHONY: doczip
doczip: doc/index.rst doc/conf.py
	rm -f goldbug.zip
	cd doc; $(MAKE) clean html
	cd doc/_build/html; zip -r ../../../goldbug.zip *

.PHONY: tests
tests:
	@echo "\033[33;1mPython 2 tests\033[0m"
	python tests/ciphertest.py
	python tests/freqtest.py
	python tests/utiltest.py
	@echo
	@echo "\033[33;1mPython 3 tests\033[0m"
	python3 tests/ciphertest.py
	python3 tests/freqtest.py
	python3 tests/utiltest.py

.PHONY: clean
clean:
	cd doc; $(MAKE) clean
	rm -f MANIFEST goldbug.zip
	find . -name "*.pyc" -delete
