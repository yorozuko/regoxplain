BINARY := regoxplain
FIXTURES := testdata/policies

.PHONY: build test race lint index demo clean

build:
	go build -o bin/$(BINARY) ./cmd/regoxplain

test:
	go test ./... -count=1

race:
	go test ./... -race -count=1

lint:
	go vet ./...

index: build
	./bin/$(BINARY) index --repo $(FIXTURES)

demo: build
	./bin/$(BINARY) search --repo $(FIXTURES) --resource google_storage_bucket_iam_member --plan testdata/plans/violating.json

clean:
	rm -rf bin
