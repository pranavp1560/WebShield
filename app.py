# importing required libraries
from flask import Flask, request, render_template
import numpy as np
import warnings
import pickle
from feature import FeatureExtraction

warnings.filterwarnings('ignore')


with open("D:\project\WebShield_final\pickle\\model6.pkl", "rb") as file:
    forest = pickle.load(file)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
       
        y_pred = forest.predict(x)[0]
        y_pro_non_phishing = forest.predict_proba(x)[0, 1]

        # Redirect to result page with prediction
        return render_template('result.html', xx=round(y_pro_non_phishing, 2), url=url)
    
    return render_template("index.html")


@app.route("/about.html")
def contact():
    return render_template("about.html")

@app.route("/faq.html")
def faq():
    return render_template("faq.html")

if __name__ == "__main__":
    app.run(debug=True)
