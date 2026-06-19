import re
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

# =====================================================================
#  PARTIE 1 : ANALYSEUR DE LIENS (ROUTE: /scan)
# =====================================================================

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
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            headers_analysis = {"accept": "application/json", "x-apikey": VT_API_KEY}
            result = requests.get(analysis_url, headers=headers_analysis).json()
            stats = result['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return {"status": "danger" if malicious > 0 or suspicious > 0 else "safe", "detec": malicious + suspicious}
    except Exception:
        return {"status": "error", "detec": 0}
    return {"status": "safe", "detec": 0}

def check_checklink(url_to_scan):
    # Liste des domaines de confiance
    domaine_whitelist = ["amazon.fr", "amazon.com", "primevideo.com", "ameli.fr", "caf.fr", "gouv.fr", "impots.gouv.fr"]
    
    # 1. Extraction du domaine
    try:
        parsed_url = urlparse(url_to_scan)
        domaine = parsed_url.netloc.lower().replace("www.", "")
        
        # Si le domaine est dans la liste blanche, on autorise sans chercher les mots-clés
        for site in domaine_whitelist:
            if domaine == site or domaine.endswith("." + site):
                return {"status": "safe", "raison": "Domaine de confiance reconnu."}
    except:
        pass 

    # 2. Analyse des mots-clés (uniquement pour les sites hors liste blanche)
    mots_cles_arnaque = ["facturation", "prime", "ameli", "caf", "colis", "infractions"]
    if any(mot in url_to_scan.lower() for mot in mots_cles_arnaque):
        return {"status": "danger", "raison": "Détection d'un mot-clé d'hameçonnage hors domaine de confiance."}
        
    return {"status": "safe", "raison": "Aucune anomalie visuelle immédiate."}


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url_to_scan = data.get("url")
    if not url_to_scan:
        return jsonify({"verdict": "Erreur", "details": "Pas d'URL fournie"}), 400
    
    vt = check_virus_total(url_to_scan)
    cl = check_checklink(url_to_scan)
    
    # Correction de l'indentation ici (tout doit être bien aligné)
    if vt["status"] == "danger" or cl["status"] == "danger":
        verdict =        "⚠️ LIEN SUSPECT ⚠️"
        
        # On personnalise le message
        if vt["status"] == "danger" and cl["status"] == "danger":
            details = f"\n\nAttention : Ce lien est identifié comme dangereux selon le système de protection O.R.I.O.N ({vt['detec']} alertes)."
        elif vt["status"] == "danger":
            details = f"Ce lien est signalé comme malveillant par {vt['detec']} outils de sécurité mondiaux (VirusTotal)."
        else:
            details = f"Le système a détecté un contenu suspect : {cl['raison']}"
            
    else:
        verdict = "              ✅ LIEN SÉCURISÉ ✅"
        details = "\n\nLe système de protection O.R.I.O.N n'a détecté aucune anomalie provenant de ce lien."
        
    return jsonify({"verdict": verdict, "details": details})


# =====================================================================
#  PARTIE 2 : BLOQUEUR DE NUMÉROS (ROUTE: /orion_shield)
# =====================================================================

def verifier_bloc_arcep(numero):
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'): num_clean = num_clean[1:]
    prefixes_spam = ["162", "163", "270", "271", "377", "378", "424", "425", "568", "569", "948", "949", "947"]
    for prefixe in prefixes_spam:
        if num_clean.startswith(prefixe): return True, "Plage de numéros officiellement réservée au Démarchage (Base ARCEP)"
    return False, None

def analyser_annuaires(numero):
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'): num_clean = num_clean[1:]
    url = f"https://www.doisjecrecrocher.fr/numero/0{num_clean}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            eval_tag = soup.find('div', class_='number-rating')
            score = eval_tag.text.strip() if eval_tag else "Inconnu"
            comments = soup.find_all('div', class_='comment-content')
            comment_text = comments[0].text.strip() if comments else "Aucun commentaire."
            return score, comment_text
    except: pass
    return "Inconnu", "Aucune donnée disponible."

@app.route('/orion_shield', methods=['POST'])
def orion_shield():
    data = request.get_json() or {}
    phone_number = data.get('phone', '')
    if not phone_number: return jsonify({"verdict": "Erreur", "details": "Aucun numéro détecté."}), 400
    
    est_un_demarcheur, motif = verifier_bloc_arcep(phone_number)
    score, top_comment = ("DANGEREUX", motif) if est_un_demarcheur else analyser_annuaires(phone_number)
    
    details = (
        f"   🛡️ O.R.I.O.N. MULTI-SHIELD 🛡️\n\n"
        f"• Numéro cible : '{phone_number}'\n"
        f"• Statut de menace : {score.upper()}\n"
        f"• Analyse : \"{top_comment}\""
    )
    return jsonify({"verdict": "Analyse Terminée", "details": details})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
