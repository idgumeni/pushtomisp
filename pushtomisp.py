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
import misp
import urllib3
urllib3.disable_warnings()

app = Flask(__name__)

print(__name__)

@app.route('/newSubmission', methods=['GET', 'POST'])
def getSubmission():
    json_dict = request.json
    #pprint(json_dict)
    sid = json_dict.get('submission',{}).get('sid',{})
    score = json_dict['score']
    descr = json_dict.get('submission',{}).get('params',{}).get('description',{})
    classif = json_dict.get('submission',{}).get('params',{}).get('classification',{})
    a_date = json_dict.get('submission',{}).get('times',{}).get('completed',{})
    print("json request: sid :",sid)
    #using sid get ontology using: /api/v4/ontology/submission/<sid>/
    mt_pool.submit(submitProcessor,sid,descr,classif,score,a_date)
    print("after thread submit:")
    return 'newSubmission done.'


def collectSessionOntology(s_id):
    #o_data=[]
    #o_data['ontology'] = []
    #o_data['tags'] = []
    submission_result={}
    
    
    # This is the connection to the Assemblyline client that we will use
    try:
        print("### ### ### collectSessionOntology")
        al_client = get_client(f"https://{config['assemblyline']['host']}:443", apikey=(config['assemblyline']['user'], config['assemblyline']['apikey']), verify=False)
        print( f"AssemblyLine client ", type(al_client))
    except Exception as e:
        print( f"Error AssemblyLine client ", e)
        return
    # client.ontology.submission(<sid>) --> /api/v4/ontology/submission/<sid>/
    try:
        #resultdata = client.submission.full(s_id) # use ontolgy
        ontology_data = al_client.ontology.submission(s_id)
    except Exception as e:
        print( f"Error getting the ontology from AssemblyLine:" ,e)
        return

   
    #logging.warning("################## #COLLECTED_IOCS"  )
    #logging.warning(o_data)
    #print("################## #","resultdata"  )
    #pprint(submission_params)
    #return [ontology_data, tags_data]
    submission_result['ontology']=ontology_data
    return submission_result



def submitProcessor(s_id,description,classification,score,analisys_date):
    print("### ### new thread sid:", str(s_id))
    misp_objects=[]
    try:
        misp_data = misp.MISP_DATA(config['misp']['url'],config['misp']['apikey'], config['misp']['content_type'])
        print( " MISP_DATA object created url:", config['misp']['url'], " type misp_data ", type(misp_data))
    except Exception as e:
        print( f"Error createing MISP_DATA url", config['misp']['url'])
        return
    
    misp_data.submission_result=collectSessionOntology(s_id)
    misp_data.ontology_result=misp_data.submission_result['ontology']
    #print( " MISP_DATA object created object type misp_data.ontology_result: ")
    #pprint(misp_data.ontology_result)
    
    misp_objects=misp_data.createFileObjects()
    print("@@@ objects created")
    try:
        # TODO initialize fields bellow from config file
        # self.event.threat_level_id = 2
        # self.event.distribution = 0
        # self.event.analysis = 1
        submission_info={'classification':classification ,'date':analisys_date,'max_score':score,'info':description }
        #pprint(submission_info)
        misp_data.createEvent(**submission_info)
    except Exception as e:
        print('error:',e)
    
    #add tag classification
    #add_attribute_tag(tag, attribute_identifier) ('classification','')
    #aggregate collected data
    #add data to MISP

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


