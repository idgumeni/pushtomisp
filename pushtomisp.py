from flask import Flask, request, jsonify
import json
import yaml
import concurrent.futures
import urllib.request
import time
import os
import logging
from assemblyline_client import get_client
from pprint import pprint



app = Flask(__name__)

print(__name__)

@app.route('/newSubmission', methods=['GET', 'POST'])
def getSubmission():
    json_dict = request.json
    #print("json request:",json_dict)
    sid = json_dict.get('sid','')
    print("json request: sid :",sid)
    #using sid get ontology using: /api/v4/ontology/submission/<sid>/
    mt_pool.submit(submitProcessor,sid)
    print("after thread submit:")
    return 'newSubmission done.'


def collectSessionOntology(s_id):
    # The result of this exercise will be stored in this variable
    COLLECTED_IOCS = dict()
    # This is the connection to the Assemblyline client that we will use
    client = get_client(f"https://{config['assemblyline']['host']}:443", apikey=(config['assemblyline']['user'], config['assemblyline']['apikey']), verify=False)
    # client.ontology.submission(<sid>) --> /api/v4/ontology/submission/<sid>/
    for record in client.ontology.submission(s_id):
        for tag_name, tag_values in record['results']['tags'].items():
            if tag_name.startswith('network'):
                # Create the tag category if does not exist
                COLLECTED_IOCS.setdefault(tag_name, [])
                # Add the IOC to our list of collected IOCs
                COLLECTED_IOCS[tag_name].extend(tag_values)
    # Now that we have gathered the IOCs, let's print them to the screen
    logging.warning("################## #","COLLECTED_IOCS"  )
    logging.warning(COLLECTED_IOCS)
    print("################## #","COLLECTED_IOCS"  )
    pprint(COLLECTED_IOCS)

def submitProcessor(s_id):
    print("new thread sid:", str(s_id))
    pprint(s_id)
    #logging.warning("new thread sid:",  str(s_id))
    #call restapi AL4 for ontology
    collectSessionOntology(s_id)
    #aggregate collected data
    #create event in MISP
    #add attribute to MISP event
    #contents = urllib.request.urlopen("http://example.com/foo/bar").read()
    #ref misp.py din cuckoo reporting
    # test with: curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:8001/newSubmission
    print("exit thread sid:",s_id)
    return "thread done";


def read_config():
    with open("config.yaml") as stream:
        try:
            conf_obj=yaml.safe_load(stream)
            #defaults
            default_port=8001
            default_host="0.0.0.0"
            default_maxthreads = 5
            default_method = "POST"
            default_ssl = False
            if conf_obj.get('pushtomisp') is None:
                print ("Missing pushtomisp settings - using defaults")
                conf_obj['pushtomisp']={}
            if conf_obj['pushtomisp'].get('network') is None:
                conf_obj['pushtomisp']['network']={}
            if  conf_obj['pushtomisp']['network'].get('address_bind') is None:  
                conf_obj['pushtomisp']['network']['address_bind'] = default_host
            if  conf_obj['pushtomisp']['network'].get('port') is None:
                conf_obj['pushtomisp']['network']['port'] = default_port
            if  conf_obj['pushtomisp']['network'].get('method') is None:
                conf_obj['pushtomisp']['network']['method'] = default_method
            if  conf_obj['pushtomisp']['network'].get('ssl') is None:
                conf_obj['pushtomisp']['network']['ssl'] = default_ssl
            if conf_obj['pushtomisp'].get('system') is None:
                conf_obj['pushtomisp']['system']={}
            if  conf_obj['pushtomisp']['system'].get('maxthreads') is None:
                conf_obj['pushtomisp']['system']['maxthreads'] = default_maxthreads
            if conf_obj.get('assemblyline') is None or conf_obj.get('misp') is None:
                exit(128)
            logging.basicConfig(filename=conf_obj['pushtomisp']['logging']['logfile'], level=getattr(logging, conf_obj["pushtomisp"]["logging"]["loglevel"].upper()))
        except yaml.YAMLError as exc:
            print(exc)
        return conf_obj


if __name__ == '__main__':
    #read conf file
    config = read_config()
    address_bind = config['pushtomisp']['network']['address_bind']
    port = config['pushtomisp']['network']['port']
    method = config['pushtomisp']['network']['method']
    ssl = config['pushtomisp']['network']['ssl']
    maxthreads = config['pushtomisp']['system']['maxthreads']
    mt_pool = concurrent.futures.ThreadPoolExecutor(max_workers=maxthreads)
    app.run(debug=True, port = port, host = address_bind)


