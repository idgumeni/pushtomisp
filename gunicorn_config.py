import os
from pushtomisp import read_config
import logging

try:
    logging.basicConfig(filename='pushtomisp.log', level='WARNING')
    configwsgi = read_config()
    address_bind = configwsgi['pushtomisp']['network']['address_bind']
    port = configwsgi['pushtomisp']['network']['port']
    method = configwsgi['pushtomisp']['network']['method']
    ssl = configwsgi['pushtomisp']['network']['ssl']
    maxthreads = configwsgi['pushtomisp']['system']['maxthreads']

    workers = int(os.environ.get('GUNICORN_PROCESSES', '1'))

    threads = int(os.environ.get('GUNICORN_THREADS', maxthreads))

    # timeout = int(os.environ.get('GUNICORN_TIMEOUT', '120'))
    bind_val=str(address_bind+':'+str(port))

    bind = os.environ.get('GUNICORN_BIND', bind_val)
    logging.warning("bind set ok"  )
except Exception as e:
    print("error gunicorn_config:",e)
    logging.warning("bins dest error"+e  )


forwarded_allow_ips = '*'

#secure_scheme_headers = { 'X-Forwarded-Proto': 'https' }