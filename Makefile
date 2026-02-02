.PHONY: lint build test package store release

lint:

build: lint
	PATH="${PATH}:${PWD}/tools" hugo build --cleanDestinationDir --minify

test: build
	tidy -errors -quiet public/**/*.html; [ $$? -le 1 ]

package: test
	./scripts/generate-release-manifest.sh
	./scripts/package-build-bundle.sh

store: package
	./scripts/store-s3-bundle.sh

release: store
	./scripts/release-set-ssm.sh