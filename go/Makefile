PROTOS := $(wildcard ../proto/*.fbs)

.PHONY: flatc
flatc: $(PROTOS)
	flatc --gen-mutable --gen-object-api --go $(PROTOS)

.PHONY: emmutaler install
emmutaler: flatc
	go build -o emmu .

install: emmutaler
	cp emmu ../bin/
