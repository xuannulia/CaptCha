PROTO_FILES := proto/captcha/v1/captcha.proto

.PHONY: proto
proto:
	PATH="$$(go env GOPATH)/bin:$$PATH" protoc -I proto \
		--go_out=. --go_opt=module=captcha \
		--go-grpc_out=. --go-grpc_opt=module=captcha \
		$(PROTO_FILES)

.PHONY: proto-check
proto-check: proto
	git diff --exit-code -- gen/captcha/v1/captcha.pb.go gen/captcha/v1/captcha_grpc.pb.go

.PHONY: smoke
smoke:
	bash scripts/smoke.sh

.PHONY: browser-smoke
browser-smoke:
	bash scripts/browser-smoke.sh

.PHONY: verify
verify:
	bash scripts/verify.sh

.PHONY: runtime-budget
runtime-budget:
	bash scripts/check-runtime-budget.sh

.PHONY: toolchain-check
toolchain-check:
	bash scripts/check-go-version.sh

.PHONY: ci-contract
ci-contract:
	bash scripts/check-ci-contract.sh

.PHONY: frontend-contract
frontend-contract:
	bash scripts/check-frontend-contract.sh

.PHONY: docker-contract
docker-contract:
	bash scripts/check-docker-contract.sh

.PHONY: http-contract
http-contract:
	bash scripts/check-http-contract.sh

.PHONY: grpc-contract
grpc-contract:
	bash scripts/check-grpc-contract.sh

.PHONY: captcha-types-contract
captcha-types-contract:
	bash scripts/check-captcha-types-contract.sh

.PHONY: browser-smoke-contract
browser-smoke-contract:
	bash scripts/check-browser-smoke-contract.sh

.PHONY: doc-commands-contract
doc-commands-contract:
	bash scripts/check-doc-commands.sh

.PHONY: docker-build
docker-build:
	docker build -f deploy/docker/Dockerfile.server .
	docker build -f deploy/docker/Dockerfile.gateway .

.PHONY: release-audit
release-audit:
	bash scripts/release-audit.sh

.PHONY: clean
clean:
	bash scripts/clean.sh
