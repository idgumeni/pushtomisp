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
    #contents = urllib.request.urlopen("http://example.com/foo/bar").read()
    #ref misp.py din cuckoo reporting
    # test with: curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:8001/newSubmission

    time.sleep(2.5)
    return "thread done";


def read_config():
    with open("config.yaml") as stream:
        try:
            conf_obj=yaml.safe_load(stream)

        except yaml.YAMLError as exc:
            print(exc)
        return conf_obj


if __name__ == '__main__':

    #defaults
    default_port=8001
    default_host="0.0.0.0"
    default_maxthreads = 5
    

    #read conf file
    config = read_config()
    

    address_bind = config['pushtomisp']['network']['address_bind'] if config['pushtomisp']['network']['address_bind'] is not None else default_host 
    port = config['pushtomisp']['network']['port'] if config['pushtomisp']['network']['port'] is not None else default_port
    maxthreads = config['pushtomisp']['system']['maxthreads'] if config['pushtomisp']['system']['maxthreads'] is not None else default_maxthreads
    
    mt_pool = concurrent.futures.ThreadPoolExecutor(max_workers=maxthreads)

    app.run(debug=True, port = port, host = address_bind)


