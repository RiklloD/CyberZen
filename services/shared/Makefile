## CyberZen shared contracts — codegen entrypoint.
##
## Requirements:
##   - protoc >= 25.0 on PATH
##   - Python: `pip install grpcio-tools`
##   - Go: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
##   - TS:  `npm i -g ts-proto`
##
## Outputs are written under generated/{python,go,ts}.

PROTO_DIR := contracts
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

PY_OUT := generated/python
GO_OUT := generated/go
TS_OUT := generated/ts

.PHONY: all python go ts clean lint check-protoc

all: python go ts

check-protoc:
	@command -v protoc >/dev/null 2>&1 || { \
		echo "protoc is required but not installed. See https://grpc.io/docs/protoc-installation/" >&2; \
		exit 1; \
	}

python: check-protoc
	@mkdir -p $(PY_OUT)
	python -m grpc_tools.protoc \
		-I. \
		--python_out=$(PY_OUT) \
		--pyi_out=$(PY_OUT) \
		$(PROTO_FILES)

go: check-protoc
	@mkdir -p $(GO_OUT)
	protoc \
		-I. \
		--go_out=$(GO_OUT) \
		--go_opt=paths=source_relative \
		$(PROTO_FILES)

ts: check-protoc
	@mkdir -p $(TS_OUT)
	protoc \
		-I. \
		--plugin=protoc-gen-ts_proto=$$(which protoc-gen-ts_proto) \
		--ts_proto_out=$(TS_OUT) \
		--ts_proto_opt=esModuleInterop=true,outputServices=false,useExactTypes=false \
		$(PROTO_FILES)

lint: check-protoc
	protoc -I. --descriptor_set_out=/dev/null $(PROTO_FILES)

clean:
	rm -rf $(PY_OUT)/*.py $(PY_OUT)/*.pyi
	find $(GO_OUT) -name '*.pb.go' -delete
	rm -rf $(TS_OUT)/*.ts
	# Preserve __init__.py, doc.go, index.ts placeholders.
	git checkout -- $(PY_OUT)/__init__.py $(GO_OUT)/doc.go $(TS_OUT)/index.ts 2>/dev/null || true
