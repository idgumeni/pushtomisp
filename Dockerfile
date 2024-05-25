FROM python:3.8


LABEL maintainer="igumeni@gmail.com"
LABEL version="0.1"
LABEL description="Docker Image for pushtomisp Assemblyline to MISP interface"

WORKDIR /pushtomisp

COPY requirements.txt requirements.txt
RUN  pip3 install -r requirements.txt

COPY *.py .
COPY conf conf
EXPOSE 8001/tcp
#VOLUME /conf
CMD [ "gunicorn", "--config" , "gunicorn_config.py", "pushtomisp:app"]
