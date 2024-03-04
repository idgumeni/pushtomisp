from flask import Flask, request, jsonify
import json

app = Flask(__name__)

print(__name__)

@app.route('/newSubmission', methods=['GET', 'POST'])
def getSubmission():
    json_object = request.json
    print(json.dumps(json_object, indent=2))
    sid = json.loads(json_object).get('sid')
    print('sid : ', sid )
    #using sid get ontology using: /api/v4/ontology/submission/<sid>/

    return 'newSubmission done.'




if __name__ == '__main__':
    app.run(debug=True, port=8001, host="0.0.0.0")