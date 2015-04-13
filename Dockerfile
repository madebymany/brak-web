FROM ubuntu:14.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update -q && apt-get install -qy python3-pip libzmq3-dev

ENV BRAK_PORT 80
EXPOSE 80

RUN mkdir -p /src/brak-web
WORKDIR /src/brak-web
ADD . .
RUN pip3 install .

ENTRYPOINT ["brak-web"]
CMD ["--logging=debug"]
