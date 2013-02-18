all:
	@echo "Targets:"
	@echo "  pypi        Build distributions and upload them to PyPI."
	@echo "  doczip      Build docs and zip them for manual upload to PyPI."
	@echo "  clean       Clear out temporary cruft."

.PHONY: pypi
pypi:
	python setup.py sdist upload

.PHONY: doczip
doczip: doc/index.rst doc/conf.py
	rm -f goldbug.zip
	cd doc; $(MAKE) clean html
	cd doc/_build/html; zip -r ../../../goldbug.zip *

.PHONY: clean
clean:
	cd doc; $(MAKE) clean
	rm -f MANIFEST goldbug.zip
	find . -name "*.pyc" -delete
