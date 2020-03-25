GO?=go
GOFLAGS?=

GOSRC!=find . -name '*.go'
GOSRC+=go.mod go.sum

akvget: $(GOSRC)
	$(GO) build $(GOFLAGS) \
		-o $@