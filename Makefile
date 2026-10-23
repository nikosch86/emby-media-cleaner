PYTHON ?= python3

.PHONY: test check

test:
	$(PYTHON) -m coverage erase
	cd tests && $(PYTHON) -m unittest -v
	$(PYTHON) -m coverage combine -q
	$(PYTHON) -m coverage report --fail-under=90

check:
	$(PYTHON) -m pylint --rcfile=.pylintrc main.py tests
