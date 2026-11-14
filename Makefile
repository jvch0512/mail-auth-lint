GHC ?= ghc

build:
	mkdir -p _build && $(GHC) -O1 -Wall -isrc -outputdir _build -o mail-auth-lint app/Main.hs

test:
	mkdir -p _build/t && $(GHC) -O0 -isrc -outputdir _build/t -o tests/spec tests/Spec.hs
	./tests/spec

sample: build
	./mail-auth-lint examples/zone.txt > docs/sample-output.txt
	./mail-auth-lint examples/zone.txt --html > site/index.html
