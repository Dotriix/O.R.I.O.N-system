import re
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from urllib.parse import urlparse

# UNE SEULE ET UNIQUE APPLICATION FLASK POUR TOUT LE MONDE
app = Flask(__name__)

# =====================================================================
#  PARTIE 1 : ANALYSEUR DE LIENS (ROUTE: /scan)
# =====================================================================

def check_virus_total(url_to_scan):
    try:
        # Simulation
        return {"status": "safe", "detec": 0}
    except Exception:
        return {"status": "error", "detec": 0}

def check_checklink(url_to_scan):
    domaine_whitelist = ["amazon.fr", "amazon.com", "ameli.fr", "caf.fr", "gouv.fr", "impots.gouv.fr"]
    
    # 1. Analyse du domaine (toujours prioritaire pour éviter les faux positifs)
    try:
        parsed_url = urlparse(url_to_scan)
        domaine = parsed_url.netloc.lower()
        
        for site in domaine_whitelist:
            if domaine == site or domaine.endswith("." + site):
                return {"status": "safe", "raison": "Domaine de confiance reconnu."}
    except Exception as e:
        print(f"DEBUG: Erreur urlparse = {e}")

    # 2. Analyse large des mots-clés (détection maximale)
    # On cherche le mot n'importe où dans l'URL sans restriction de frontières
    mots_cles_arnaque = ["facturation", "prime", "amende", "vinted", "colis", "urssaf", "caf", "ameli", "infraction"]
    url_basse = url_to_scan.lower()
    
    for mot in mots_cles_arnaque:
        if mot in url_basse:
             return {"status": "danger", "raison": f"Mot-clé '{mot}' détecté dans l'URL."}
        
    return {"status": "safe", "raison": "Aucune anomalie visuelle immédiate."}


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url_to_scan = data.get("url", "")

    if not url_to_scan:
        return jsonify({"verdict": "Erreur", "details": "Pas d'URL reçue"}), 400

    vt_result = check_virus_total(url_to_scan)
    cl_result = check_checklink(url_to_scan)

    nb_alertes = 0
    if vt_result["status"] == "danger": 
        nb_alertes += vt_result['detec']
    if cl_result["status"] == "danger": 
        nb_alertes += 1

    # On vérifie si une menace est détectée par l'un des deux outils
    if nb_alertes > 0 or cl_result["status"] == "danger":
        # Sécurité : s'assurer d'afficher au moins 1 menace si le statut est danger
        total_menaces = max(1, nb_alertes)
        
        verdict = "                   ⚠️ MENACE ⚠️"
        
        # Gestion propre et dynamique du français selon le nombre de menaces
        if total_menaces == 1:
            details = f"\n\nLe système O.R.I.O.N a détecté 1 menace. {cl_result['raison']}"
        else:
            details = f"\n\nLe système O.R.I.O.N a détecté {total_menaces} menaces. {cl_result['raison']}"
    else:
        verdict = "                  ✅ SÉCURISÉ ✅"
        details = "\n\nCe lien a été vérifié avec succès et ne présente aucun risque."

    return jsonify({"verdict": verdict, "details": details})



# =====================================================================
#  PARTIE 2 : BLOQUEUR DE NUMÉROS (ROUTE: /orion_shield)
# =====================================================================

def verifier_bloc_arcep(numero):
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'):
        num_clean = num_clean[1:]
    prefixes_spam = ["162", "163", "270", "271", "377", "378", "424", "425", "568", "569", "948", "949", "947"]
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
    app.run(host='0.0.0.0', port=10000)
