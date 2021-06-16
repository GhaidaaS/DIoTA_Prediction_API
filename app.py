from flask import Flask, request
from flask import jsonify
from mypackage.predict import Predict
app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
  # get request data
  req_data = request.get_json()
  # create object from predict class and pass json data to it
  p = Predict(req_data)
  # call run function to get prediction result
  results = p.run(req_data)
  # return json data to the web-app
  return jsonify(results)

if __name__ == "__main__":
  app.run(debug=True)
