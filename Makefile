.PHONY: all clean documentation documentation-html documentation-pdf

all: documentation

documentation: documentation-html documentation-pdf

documentation-html:
	$(MAKE) -C doc html

documentation-pdf:
	$(MAKE) -C doc latexpdf

clean:
	$(MAKE) -C doc clean
	if test -d doc/build; then rmdir doc/build; fi
