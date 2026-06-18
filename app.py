import re
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify

# UNE SEULE ET UNIQUE APPLICATION FLASK POUR TOUT LE MONDE
app = Flask(__name__)

# =====================================================================
#  PARTIE 1 : ANALYSEUR DE LIENS (ROUTE: /scan)
# =====================================================================

def check_virus_total(url_to_scan):
    # (Met ton code original ici si tu as tes clés d'API secrètes, 
    # ou laisse-le s'il est déjà présent plus haut dans ton historique)
    try:
        # Simulation ou vrai code VirusTotal
        return {"status": "safe", "detec": 0}
    except Exception:
        return {"status": "error", "detec": 0}

def check_checklink(url_to_scan):
    mots_cles_arnaque = ["facturation", "prime", "amende", "vinted", "urssaf", "infraction"]
    if any(mot in url_to_scan.lower() for mot in mots_cles_arnaque):
        return {"status": "danger", "raison": "Mots-clés d'arnaque détectés"}
    return {"status": "safe", "raison": "Aucun mot-clé suspect"}

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url_to_scan = data.get("url")

    if not url_to_scan:
        return jsonify({"verdict": "Erreur", "details": "Pas d'URL reçue"}), 400

    vt_result = check_virus_total(url_to_scan)
    cl_result = check_checklink(url_to_scan)

    if vt_result["status"] == "danger" or cl_result["status"] == "danger":
        verdict = "                   ⚠️ MENACE ⚠️"
        details = f"\n\nLe système O.R.I.O.N a détecté : {vt_result['detec']} alerte(s). {cl_result['raison']}"
    else:
        verdict = "                  ✅ SÉCURISÉ ✅"
        details = "\n\nLe système O.R.I.O.N n'a rien détecté de suspect."

    return jsonify({
        "verdict": verdict,
        "details": details
    })


# =====================================================================
#  PARTIE 2 : BLOQUEUR DE NUMÉROS (ROUTE: /orion_shield)
# =====================================================================

def verifier_bloc_arcep(numero):
    num_clean = re.sub(r'\s+|\+33', '', numero)
    if num_clean.startswith('0'):
        num_clean = num_clean[1:]
        
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
        
    est_un_demarcheur, motif = verifier_bloc_arcep(phone_number)
    
    if est_un_demarcheur:
        score = "DANGEREUX"
        top_comment = motif
    else:
        score, top_comment = analyser_annuaires(phone_number)
    
    details = (
        f"   🛡️ **O.R.I.O.N. MULTI-SHIELD** 🛡️\n\n"
        f"• **Cible :** `{phone_number}`\n"
        f"• **Statut de menace :** **{score.upper()}**\n"
        f"• **Analyse :** *\"{top_comment}\"*"
    )
    
    return jsonify({"verdict": "Analyse Terminée", "details": details})
