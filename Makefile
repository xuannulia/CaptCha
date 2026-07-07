PROTO_FILES := proto/captcha/v1/captcha.proto
GENERATED_PROTO_FILES := gen/captcha/v1/captcha.pb.go gen/captcha/v1/captcha_grpc.pb.go
DOCKER_GOPROXY ?= https://goproxy.cn,direct
DOCKER_GOSUMDB ?= sum.golang.google.cn

.PHONY: proto
proto:
	PATH="$$(go env GOPATH)/bin:$$PATH" protoc -I proto \
		--go_out=. --go_opt=module=captcha \
		--go-grpc_out=. --go-grpc_opt=module=captcha \
		$(PROTO_FILES)

.PHONY: proto-check
proto-check:
	tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	for file in $(GENERATED_PROTO_FILES); do \
		mkdir -p "$$tmp_dir/$$(dirname "$$file")"; \
		cp "$$file" "$$tmp_dir/$$file"; \
	done; \
	$(MAKE) proto; \
	for file in $(GENERATED_PROTO_FILES); do \
		if ! cmp -s "$$tmp_dir/$$file" "$$file"; then \
			echo "Generated protobuf file is not up to date: $$file" >&2; \
			exit 1; \
		fi; \
	done; \
	echo "PASS: generated protobuf files are up to date"

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
	docker build --build-arg GOPROXY="$(DOCKER_GOPROXY)" --build-arg GOSUMDB="$(DOCKER_GOSUMDB)" -f deploy/docker/Dockerfile.server .
	docker build --build-arg GOPROXY="$(DOCKER_GOPROXY)" --build-arg GOSUMDB="$(DOCKER_GOSUMDB)" -f deploy/docker/Dockerfile.gateway .

.PHONY: release-audit
release-audit:
	bash scripts/release-audit.sh

.PHONY: synthetic-bot-tracks
synthetic-bot-tracks:
	mkdir -p output
	go run ./scripts/generate-bot-tracks.go -out output/synthetic-bot-tracks.jsonl

.PHONY: clean
clean:
	bash scripts/clean.sh
