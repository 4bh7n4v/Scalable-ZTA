from flask import Flask, jsonify
app = Flask(__name__)
AUTH_STATE = {"authenticated": False}

@app.route('/')
def index():
    return jsonify({
        "system": "Zero Trust Policy API",
        "status": "Running",
        "endpoints": ["/auth", "/auth/allow", "/auth/block"]
    })

@app.get("/auth")
def auth():
   
    return jsonify(AUTH_STATE)

@app.get("/auth/allow")
def allow():
    AUTH_STATE["authenticated"] = True
    return jsonify({"status": "client authorized", "sdn_action": "INSTALL_FLOW"})

@app.get("/auth/block")
def block():
    AUTH_STATE["authenticated"] = False
    return jsonify({"status": "client blocked", "sdn_action": "REMOVE_FLOW"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)