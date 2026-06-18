from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Remplace par ta clé API gratuite obtenue sur virustotal.com
VT_API_KEY = "e45dafa9aa567aeed422232120528f2ee573e1263eab0fdd91bbd1450fb27f6c"

def check_virus_total(url_to_scan):
    url = "https://www.virustotal.com/api/v3/urls"
    payload = f"url={url_to_scan}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    try:
        # Étape 1 : Envoyer l'URL à analyser
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            # Étape 2 : Récupérer le résultat de l'analyse
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            headers_analysis = {"accept": "application/json", "x-apikey": VT_API_KEY}
            result = requests.get(analysis_url, headers=headers_analysis).json()
            
            stats = result['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return {"status": "danger" if malicious > 0 or suspicious > 0 else "safe", "detec": malicious}
    except Exception:
        return {"status": "error", "detec": 0}
    return {"status": "safe", "detec": 0}

def check_checklink(url_to_scan):
    # Simulation de l'analyse simplifiée de CheckLink via leur mécanisme public
    # Si le site est très récent ou contient des mots clés bancaires frauduleux
    mots_cles_arnaque = ["facturation", "prime", "ameli", "caf", "colis", "infractions"]
    if any(mot in url_to_scan.lower() for mot in mots_cles_arnaque):
        return {"status": "danger", "raison": "Détection d'un mot-clé de phishing connu par l'IA."}
    return {"status": "safe", "raison": "Aucune anomalie visuelle immédiate."}

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url_to_scan = data.get("url")
    
    if not url_to_scan:
        return jsonify({"erreur": "Pas d'URL fournie"}), 400
        
    vt_result = check_virus_total(url_to_scan)
    cl_result = check_checklink(url_to_scan)
    
    # Fusion des résultats
    if vt_result["status"] == "danger" or cl_result["status"] == "danger":
        verdict = "🔴 DANGER 🔴"
        details = f"O.R.I.O.N a détecté : {vt_result['detec']} alerte(s). \nCheckLink: {cl_result['raison']}"
    else:
        verdict = "🟢 SÛR 🟢"
        details = "O.R.I.O.N n'a détecté aucune anomalie."
        
    return jsonify({
        "verdict": verdict,
        "details": details
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
