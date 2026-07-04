.PHONY: build test docker-build up down logs tidy install

build:
	cd agent && go build ./cmd/infracheck-agent

test:
	cd agent && go test ./...

tidy:
	cd agent && go mod tidy

docker-build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

install:
	sh scripts/install-linux.sh
