.PHONY: build-container run prepare

docker:
	docker build -t arrowpass/taproot_workshop -f Dockerfile.build .
	# docker push arropass/taproot_workshop

run:
	docker run -d -p 8888:8888 --name notebook

prepare:
	cp config.ini.sample config.ini
