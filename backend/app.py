from flask import Flask, request, jsonify
import pickle
import sqlite3
import numpy as np
from flask_cors import CORS
import pandas as pd

app = Flask(__name__)
CORS(app)

# -------------------------
# DATABASE INITIAL SETUP
# -------------------------
def init_db():
    conn = sqlite3.connect("database.sqlite")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# -------------------------
# LOAD ML MODEL
# -------------------------
model = pickle.load(open("model.pkl", "rb"))

# -------------------------
# REGISTER API
# -------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    name = data["name"]
    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect("database.sqlite")
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, password))
        conn.commit()
        return jsonify({"status": "success", "message": "User registered!"})
    except:
        return jsonify({"status": "error", "message": "Email already exists"})

# -------------------------
# LOGIN API
# -------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect("database.sqlite")
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
    user = cur.fetchone()

    if user:
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"})

# -------------------------
# PREDICTION API
# -------------------------
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json

    temperature = data['temperature']
    humidity = data['humidity']
    rainfall = data['rainfall']
    ndvi = data['ndvi']
    water_index = data['water_index']

    sample = np.array([[temperature, humidity, rainfall, ndvi, water_index]])
    prediction = model.predict(sample)[0]

    labels = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}

    return jsonify({"risk": labels[prediction]})

# -------------------------
# GET DISTRICT DATA
# -------------------------
@app.route("/getDistrictData", methods=["POST"])
def getDistrictData():
    import pandas as pd

    data = request.json
    district = data.get("district", "").strip()

    print("Requested district:", district)

    df = pd.read_csv("india_disease_data.csv")

    # Normalize
    df["district_clean"] = df["district"].str.lower().str.strip()
    district_clean = district.lower().strip()

    df2 = df[df["district_clean"] == district_clean]

    if df2.empty:
        return jsonify({
            "temperature": "No data",
            "humidity": "No data",
            "rainfall": "No data",
            "risk": "No data",
            "history": []
        })

    avg_temp = round(df2["temperature"].mean(), 2)
    avg_hum = round(df2["humidity"].mean(), 2)
    avg_rain = round(df2["rainfall"].mean(), 2)

    sample = model.predict([[avg_temp, avg_hum, avg_rain, 0.5, 0.5]])[0]
    risk = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}[sample]

    history = df2[["year", "cases"]].to_dict(orient="records")

    return jsonify({
        "temperature": avg_temp,
        "humidity": avg_hum,
        "rainfall": avg_rain,
        "risk": risk,
        "history": history
    })

# -------------------------
# RUN SERVER
# -------------------------
if __name__ == "__main__":
    app.run(port=5000, debug=True)
