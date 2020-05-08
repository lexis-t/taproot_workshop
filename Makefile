.PHONY: build-container run

docker:
	docker build -t arrowpass/taproot_workshop -f Dockerfile.build .
	# docker push arropass/taproot_workshop

run:
	docker run -d -p 8888:8888 --name notebook

