.PHONY: docker docker-push test prepare jupyter

docker:
	docker build -t arrowpass/taproot_workshop -f Dockerfile.build .

docker-push: docker
	docker push arrowpass/taproot_workshop

jupyter:
	docker-compose up jupyter

test:
	docker-compose up test

prepare:
	cp config.ini.sample config.ini
