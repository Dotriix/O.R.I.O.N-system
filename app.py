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
        return {"status": "danger", "raison": "Détection d'un mot-clé d'hameçonnage connu de sa base de données."}
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
        verdict = "                   ⚠️ MENACE ⚠️"
        details = f"\n\nLe système O.R.I.O.N a détecté : {vt_result['detec']} alerte(s). {cl_result['raison']}"
    else:
        verdict = "                  ✅ SÉCURISÉ ✅"
        details = "\n\nLe système O.R.I.O.N n'a détecté aucune anomalie."
        
    return jsonify({
        "verdict": verdict,
        "details": details
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# Bloqueur d'appels 
import re
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify

app = Flask(__name__)

def verifier_bloc_arcep(numero):
    """
    Simule la logique de Saracroche en vérifiant les préfixes 
    officiellement dédiés au démarchage en France (Arcep).
    """
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'):
        num_clean = num_clean[1:]
        
    # Liste des préfixes officiels du démarchage (0162, 0163, 0270, 0948, etc.)
    prefixes_spam = [
        "162", "163", "270", "271", "377", "378", "424", "425", 
        "568", "569", "948", "949", "947"
    ]
    
    for prefixe in prefixes_spam:
        if num_clean.startswith(prefixe):
            return True, "Plage de numéros officiellement réservée au Démarchage (Base ARCEP)"
    return False, None

def analyser_annuaires(numero):
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'):
        num_clean = num_clean[1:]
        
    url = f"https://www.doisjecrecrocher.fr/numero/0{num_clean}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            eval_tag = soup.find('div', class_='number-rating')
            score = eval_tag.text.strip() if eval_tag else "Inconnu"
            
            comments = soup.find_all('div', class_='comment-content')
            comment_text = comments[0].text.strip() if comments else "Aucun commentaire."
            return score, comment_text
    except:
        pass
    return "Inconnu", "Aucune donnée disponible."

@app.route('/orion_shield', methods=['POST'])
def orion_shield():
    data = request.get_json() or {}
    phone_number = data.get('phone', '')
    
    if not phone_number:
        return jsonify({"verdict": "Erreur", "details": "Aucun numéro détecté."}), 400
        
    # 1. Analyse style Saracroche (ARCEP)
    est_un_demarcheur, motif = verifier_bloc_arcep(phone_number)
    
    if est_un_demarcheur:
        score = "DANGEREUX"
        top_comment = motif
    else:
        # 2. Si ce n'est pas dans les blocs ARCEP, on interroge l'annuaire de masse
        score, top_comment = analyser_annuaires(phone_number)
    
    # Rendu final pour l'action "Afficher le contenu" de l'iPhone
    details = (
        f"   🛡️ **O.R.I.O.N. MULTI-SHIELD** 🛡️\n\n"
        f"• **Cible :** `{phone_number}`\n"
        f"• **Statut de menace :** **{score.upper()}**\n"
        f"• **Analyse :** *\"{top_comment}\"*"
    )
    
    return jsonify({"verdict": "Analyse Terminée", "details": details})
