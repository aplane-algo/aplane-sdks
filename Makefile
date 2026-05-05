.PHONY: test go-test python-test typescript-test clean

test: go-test python-test typescript-test

go-test:
	cd go && go test ./...

python-test:
	cd python && pytest -v

typescript-test:
	cd typescript && npm test

clean:
	rm -rf python/.pytest_cache python/build python/dist python/*.egg-info
	rm -rf typescript/dist typescript/*.tgz
