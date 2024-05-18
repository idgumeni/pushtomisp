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


logging.warning("app name:"+__name__  )
@app.route('/newSubmission', methods=['GET', 'POST'])
def getSubmission():
    json_dict = request.json
    config = read_config()
    sid = json_dict.get('submission',{}).get('sid',{})
    score = json_dict['score']
    descr = json_dict.get('submission',{}).get('params',{}).get('description',{})
    classif = json_dict.get('submission',{}).get('params',{}).get('classification',{})
    a_date = json_dict.get('submission',{}).get('times',{}).get('completed',{})
    #using sid get ontology using: /api/v4/ontology/submission/<sid>/
    #mt_pool.submit(submitProcessor,sid,descr,classif,score,a_date) #no lponger need it - gunicorn is doing multithreading
    misp_objects=[]
    try:
        default_sys_data={'tool_name':config['assemblyline']['tool_name'], 'analysis':config['misp']['analysis'], 'threat_level_id':config['misp']['threat_level_id'],'distribution':config['misp']['distribution'], }
        misp_data = misp.MISP_DATA(config['misp']['url'],config['misp']['apikey'], config['misp']['content_type'], **default_sys_data)
        print( " MISP_DATA object created url:", config['misp']['url'], " type misp_data ", type(misp_data))
    except Exception as e:
        print( f"Error createing MISP_DATA url", config['misp']['url'], " e:", e)
        return
    
    misp_data.submission_result=collectSessionOntology(sid,config)
    misp_data.ontology_result=misp_data.submission_result['ontology']
    logging.warning( " MISP_DATA object created object type misp_data.ontology_result")
    
    try:
        with open('ontology_data.json',"+a") as fh:
            fh.write("\nsid:"+str(sid) + "\n")
            fh.write(json.dumps(misp_data.ontology_result))
    except Exception as e:
        print("error adding ontology data in json file:", e)

    misp_objects=misp_data.createFileObjects()
    
    try:
        submission_info={'classification':classif ,'date':a_date,'max_score':score,'info':descr }
        misp_data.createEvent(**submission_info)
    except Exception as e:
        print('error:',e)
    
    return 'newSubmission done.'


def collectSessionOntology(s_id, config):
    submission_result={}
    
    # This is the connection to the Assemblyline client that we will use
    try:
        print("### ### ### collectSessionOntology")
        al_client = get_client(f"https://{config['assemblyline']['host']}:443", apikey=(config['assemblyline']['user'], config['assemblyline']['apikey']), verify=False)
        print( f"AssemblyLine client ", type(al_client))
    except Exception as e:
        print( f"Error AssemblyLine client ", e)
        return
    try:
        #resultdata = client.submission.full(s_id) # use ontolgy
        ontology_data = al_client.ontology.submission(s_id)
    except Exception as e:
        print( f"Error getting the ontology from AssemblyLine:" ,e)
        return

    submission_result['ontology']=ontology_data
    return submission_result





def read_config():
    with open("./conf/config.yaml") as stream:
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
        except Exception as exc:
            print("Error parse conf gile: ",exc)
            logging.warning("Error parse conf gile: "+exc)
        return conf_obj



    


