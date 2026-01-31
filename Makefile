.PHONY: lint build test package store release

lint:

build: lint
	PATH="${PATH}:${PWD}/tools" hugo build --cleanDestinationDir --minify

test: build
	tidy -errors -quiet public/**/*.html; [ $$? -le 1 ]

package: test
	./scripts/package-build-bundle.sh

store: package
	@echo "$(shell date +%s).$(shell git rev-parse --short HEAD)" > .release-id
	@echo "==> release id: $$(cat .release-id)"
	./scripts/store-s3-bundle.sh

release: store
	./scripts/release-set-ssm.sh