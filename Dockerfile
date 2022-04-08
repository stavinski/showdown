
FROM python:3-alpine as build

LABEL org.opencontainers.image.authors="Michael Cromwell"

COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

COPY . /app

WORKDIR /app

ENTRYPOINT [ "python", "./showdown.py" ]