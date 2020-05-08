# Container for running
FROM arrowpass/taproot_workshop

ADD . /app
WORKDIR /app

EXPOSE 8888

# RUN jupyter notebook --ip=0.0.0.0 --port=8888 --allow-root
