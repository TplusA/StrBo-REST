.PHONY: all clean check check-relaxed documentation documentation-html documentation-pdf

PYTHONFILES = $(wildcard *.py strbo/*.py)

FLAKE8 = flake8
FLAKE8_OPTIONS = --exit-zero

all:
	@echo 'Valid make targets:'
	@echo '  documentation - Generate API documentation'
	@echo '  documentation-html - Generate API documentation in HTML format only'
	@echo '  documentation-pdf  - Generate API documentation in PDF format only'
	@echo '  check         - Analyze code with pyflakes and ${FLAKE8}'
	@echo '  check-relaxed - Analyze code with relaxed setting, ignoring some issues'
	@echo '  clean         - Remove all generated files'

check: check-relaxed
	python3 -m ${FLAKE8} $(PYTHONFILES)

check-relaxed:
	python3 -m pyflakes $(PYTHONFILES)
	python3 -m ${FLAKE8} ${FLAKE8_OPTIONS} --ignore=E501,W504 $(PYTHONFILES)

documentation: documentation-html documentation-pdf

documentation-html:
	$(MAKE) -C doc html

documentation-pdf:
	$(MAKE) -C doc latexpdf

clean:
	$(MAKE) -C doc clean
	if test -d doc/build; then rmdir doc/build; fi
	rm -rf strbo/__pycache__
