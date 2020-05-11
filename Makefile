.PHONY: docker build run prepare

docker:
	docker build -t arrowpass/taproot_workshop -f Dockerfile.build .
	docker push arropass/taproot_workshop

build:
	docker build --tag taproot_workshop_run .

run: build
	docker run -p 8888:8888 taproot_workshop_run jupyter notebook --ip=0.0.0.0 --port=8888 --allow-root

prepare:
	cp config.ini.sample config.ini
