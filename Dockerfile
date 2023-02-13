#FROM alpine:3.17.2
FROM python:alpine3.16
RUN mkdir -p /app
WORKDIR /app

RUN apk update
RUN apk add py3-pip
COPY ./requirements.txt /tmp/
ENV PIP_ROOT_USER_ACTION=ignore
RUN pip3 install --root-user-action=ignore -r /tmp/requirements.txt --use-pep517

COPY index.py /app

CMD ["/usr/local/bin/python3","-u", "/app/index.py"]