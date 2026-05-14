.PHONY: test go-test python-test typescript-test integration-test go-integration-test python-integration-test typescript-integration-test clean

test: go-test python-test typescript-test

go-test:
	cd go && go test ./...

python-test:
	cd python && pytest -v

typescript-test:
	cd typescript && npm test

integration-test: go-integration-test python-integration-test typescript-integration-test

go-integration-test:
	cd go && APLANE_SDK_INTEGRATION=1 go test -run Integration -count=1 ./...

python-integration-test:
	cd python && APLANE_SDK_INTEGRATION=1 pytest -v tests/test_integration.py

typescript-integration-test:
	cd typescript && APLANE_SDK_INTEGRATION=1 node --import tsx --test integration/live_signer.test.ts

clean:
	rm -rf python/.pytest_cache python/build python/dist python/*.egg-info
	rm -rf typescript/dist typescript/*.tgz
