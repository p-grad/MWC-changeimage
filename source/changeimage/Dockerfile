FROM docker.io/python:3.8.9-alpine

LABEL maintainer=piotr.grad.pg@gmail.com

COPY ./requirements.txt /app/

WORKDIR /app

RUN apk add --update --no-cache bind-tools ca-certificates
RUN apk add --update --no-cache bind-tools ca-certificates gcc musl-dev python3-dev libffi-dev openssl-dev

RUN /usr/local/bin/python -m pip install --upgrade pip
RUN pip install pipenv
RUN pipenv install -r ./requirements.txt

RUN pipenv install --system --deploy

COPY ./changeimage.py /app/
COPY ./config.py /app/

CMD ["gunicorn", "changeimage:app", "--config=config.py"]
