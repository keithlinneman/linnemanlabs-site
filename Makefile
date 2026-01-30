.PHONY: build

build:
	# hmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
	rm -rf public/
	PATH="${PATH}:${PWD}/tools" hugo build --minify

all: build