PREFIX := $(CURDIR)/.deps
ASN1C := $(PREFIX)/bin/asn1c

all: deps

# One-time: build the vendored asn1c. `export ASN1C=$(ASN1C)` before cargo build.
deps: $(ASN1C)
	@echo 'export ASN1C=$(ASN1C)'

$(ASN1C):
	mkdir -p .deps-build
	cd dependencies/asn1c && autoreconf -ivf
	cd .deps-build && ../dependencies/asn1c/configure --prefix=$(PREFIX)
	$(MAKE) -C .deps-build && $(MAKE) -C .deps-build install

.PHONY: all deps
