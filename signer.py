import os
import sys
import glob
import getpass
import subprocess
import tempfile

# --- Reglages a adapter ---
MODULE = ""       # laisser vide pour detection automatique
LABEL_CERT = ""   # libelle du certificat, vu avec pkcs11-tool -O
ID_CLE = ""       # identifiant de la cle en hexadecimal, ex. "01"
SLOT_TOKEN = ""   # libelle du token, laisser vide si une seule cle
# --------------------------

CHEMINS_MODULE = [
    "/usr/lib/*/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/pkcs11/opensc-pkcs11.so",
]


def trouve_module():
    if MODULE:
        return MODULE
    for motif in CHEMINS_MODULE:
        trouves = glob.glob(motif)
        if trouves:
            return trouves[0]
    raise RuntimeError("Module opensc-pkcs11.so introuvable : renseigner MODULE dans signer.py")


def signer_pdf(chemin, pin, module):
    from pyhanko.sign import signers, fields
    from pyhanko.sign.pkcs11 import PKCS11SigningContext, open_pkcs11_session
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    sortie = chemin[:-4] + "_signe.pdf"
    session = open_pkcs11_session(
        module,
        user_pin=pin,
        token_label=SLOT_TOKEN or None,
    )
    try:
        contexte = PKCS11SigningContext(
            session,
            cert_label=LABEL_CERT or None,
            key_id=bytes.fromhex(ID_CLE) if ID_CLE else None,
        )
        signataire = contexte.signer
        meta = signers.PdfSignatureMetadata(field_name="Signature1")
        with open(chemin, "rb") as entree:
            ecrivain = IncrementalPdfFileWriter(entree)
            fields.append_signature_field(
                ecrivain, fields.SigFieldSpec(sig_field_name="Signature1")
            )
            with open(sortie, "wb") as fichier_sortie:
                signers.sign_pdf(ecrivain, meta, signer=signataire, output=fichier_sortie)
    finally:
        session.close()
    return sortie


def signer_detache(chemin, pin, module):
    """Signature CMS detachee via OpenSSL et le moteur pkcs11."""
    sortie = chemin + ".p7s"
    parties = []
    if SLOT_TOKEN:
        parties.append(f"token={SLOT_TOKEN}")
    if ID_CLE:
        parties.append(f"id=%{ID_CLE[:2]}")
    base = "pkcs11:" + ";".join(parties)
    sep = ";" if parties else ""
    uri_cle = base + sep + "type=private"
    uri_cert = base + sep + "type=cert"

    config = (
        "openssl_conf = openssl_init\n"
        "[openssl_init]\nengines = engine_section\n"
        "[engine_section]\npkcs11 = pkcs11_section\n"
        "[pkcs11_section]\n"
        "engine_id = pkcs11\n"
        f"MODULE_PATH = {module}\n"
        f"PIN = {pin}\n"
        "init = 0\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as cfg:
        os.chmod(cfg.name, 0o600)
        cfg.write(config)
        chemin_cfg = cfg.name
    try:
        env = dict(os.environ, OPENSSL_CONF=chemin_cfg)
        commande = [
            "openssl", "cms", "-sign", "-binary",
            "-in", chemin, "-outform", "DER", "-out", sortie,
            "-engine", "pkcs11", "-keyform", "engine",
            "-inkey", uri_cle, "-signer", uri_cert,
            "-md", "sha256",
        ]
        resultat = subprocess.run(commande, env=env, capture_output=True, text=True)
        if resultat.returncode != 0:
            raise RuntimeError(resultat.stderr.strip())
    finally:
        os.remove(chemin_cfg)
    return sortie


def main():
    if len(sys.argv) < 2:
        print("Usage : ./lancer.sh fichier [fichier2 ...]")
        sys.exit(1)
    module = trouve_module()
    pin = getpass.getpass("Code PIN de la cle : ")
    for chemin in sys.argv[1:]:
        if not os.path.isfile(chemin):
            print(f"Introuvable : {chemin}")
            continue
        try:
            if chemin.lower().endswith(".pdf"):
                sortie = signer_pdf(chemin, pin, module)
            else:
                sortie = signer_detache(chemin, pin, module)
            print(f"Signe : {sortie}")
        except Exception as erreur:
            print(f"Echec pour {chemin} : {erreur}")


if __name__ == "__main__":
    main()