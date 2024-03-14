from flask import Flask, request, jsonify
import json
import yaml
import concurrent.futures
import urllib.request
import time

app = Flask(__name__)

print(__name__)

@app.route('/newSubmission', methods=['GET', 'POST'])
def getSubmission():
    json_dict = request.json
    print("json request:",json_dict)
    sid = json_dict.get('sid',{})

    #using sid get ontology using: /api/v4/ontology/submission/<sid>/
    mt_pool.submit(submitProcessor,sid)

    return 'newSubmission done.'


def submitProcessor(s_id):
    print("new thread sid:" + s_id)
    #call restapi AL4 for ontology
    #aggregate collected data
    #create event in MISP
    #add attribute to MISP event
    #contents = urllib.request.urlopen("http://example.com/foo/bar").read()
    #ref misp.py din cuckoo reporting
    # test with: curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:8001/newSubmission

    time.sleep(10)
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


