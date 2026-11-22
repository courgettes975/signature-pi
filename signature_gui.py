# signature_gui.py : signature numerique avec une cle a certificat (plein ecran, tactile)
import os
import sys
import subprocess
import threading
import importlib.util
import tkinter as tk
from tkinter import filedialog, simpledialog

import habillage as H
import signer


def verifie_cle():
    """Retourne (texte, couleur, module). Cherche une cle PKCS#11 branchee."""
    try:
        module = signer.trouve_module()
    except Exception:
        return "Module OpenSC introuvable", H.ROUGE, None
    try:
        r = subprocess.run(["pkcs11-tool", "--module", module, "-L"], capture_output=True, text=True, timeout=12)
        sortie = r.stdout + r.stderr
    except FileNotFoundError:
        return "pkcs11-tool absent (installer opensc)", H.ROUGE, module
    except Exception as e:
        return "Lecture impossible : %s" % e, H.ROUGE, module
    for ligne in sortie.splitlines():
        if "token label" in ligne:
            return "Cle detectee : " + ligne.split(":", 1)[1].strip(), H.VERT, module
    if "No slots" in sortie:
        return "Aucune cle branchee", H.ORANGE, module
    return "Lecteur present, pas de cle", H.ORANGE, module


def moteur_openssl():
    try:
        r = subprocess.run(["openssl", "engine", "-t", "pkcs11"], capture_output=True, text=True, timeout=8)
        return "available" in (r.stdout + r.stderr)
    except Exception:
        return False


class Application:
    def __init__(self, racine, fichiers, taille=None):
        self.racine = racine
        s = H.prepare(racine, taille)
        self.fichiers = [os.path.abspath(f) for f in fichiers if os.path.isfile(f)]
        self.cle = ("Verification de la cle...", H.SOUS, None)
        self.pdf_ok = importlib.util.find_spec("pyhanko") is not None and importlib.util.find_spec("pkcs11") is not None
        self.openssl_ok = None
        self.resultats = []
        self.en_cours = False
        self.E = H.Ecran(racine, s, "Signature", "stylo", H.VIOLET, self.dessine)
        racine.after(300, self.verifie)

    def verifie(self):
        self.cle = ("Verification de la cle...", H.SOUS, self.cle[2])
        self.E.rafraichir()

        def tache():
            resultat = verifie_cle()
            ok = moteur_openssl()
            self.racine.after(0, self.fin_verif, resultat, ok)
        threading.Thread(target=tache, daemon=True).start()

    def fin_verif(self, resultat, ok):
        self.cle = resultat
        self.openssl_ok = ok
        self.E.rafraichir()

    def nom_fichiers(self):
        if not self.fichiers:
            return "Aucun fichier choisi", H.SOUS
        noms = [os.path.basename(f) for f in self.fichiers]
        if len(noms) == 1:
            return noms[0], H.TEXTE
        return "%d fichiers : %s" % (len(noms), ", ".join(noms)), H.TEXTE

    def dessine(self, E):
        s, w = E.s, E.w
        y0 = E.haut
        # 1. fichier
        E.carte(10 * s, y0 + 8 * s, w - 10 * s, y0 + 66 * s)
        E.create_oval(20 * s, y0 + 18 * s, 56 * s, y0 + 54 * s, fill=H.FOND, outline="")
        E.icone("fichier", 38 * s, y0 + 36 * s, 11 * s, H.VIOLET, H.FOND)
        E.txt(68 * s, y0 + 21 * s, "Fichier a signer", 9, H.SOUS, "w")
        texte, col = self.nom_fichiers()
        E.txt(68 * s, y0 + 42 * s, texte, 12, col, "w", True, w - 230 * s)
        E.bouton(w - 142 * s, y0 + 18 * s, w - 20 * s, y0 + 56 * s, "Choisir", self.choisir, H.VIOLET, "dossier", 12)
        # 2. cle
        E.carte(10 * s, y0 + 74 * s, w - 10 * s, y0 + 132 * s)
        E.create_oval(20 * s, y0 + 84 * s, 56 * s, y0 + 120 * s, fill=H.FOND, outline="")
        texte, col, _ = self.cle
        E.icone("cle", 38 * s, y0 + 102 * s, 11 * s, col, H.FOND)
        E.txt(68 * s, y0 + 87 * s, "Cle de signature", 9, H.SOUS, "w")
        E.txt(68 * s, y0 + 108 * s, texte, 12, col, "w", True, w - 230 * s)
        E.bouton(w - 142 * s, y0 + 84 * s, w - 20 * s, y0 + 122 * s, "Verifier", self.verifie, H.CARTE2, "rafraichir", 12)
        # 3. capacites ou resultats
        E.carte(10 * s, y0 + 140 * s, w - 10 * s, y0 + 196 * s)
        if self.resultats:
            for k, (ok, texte) in enumerate(self.resultats[-2:]):
                y = y0 + 156 * s + k * 26 * s
                E.icone("check" if ok else "croix", 30 * s, y, 8 * s, H.VERT if ok else H.ROUGE, H.CARTE)
                E.txt(46 * s, y, texte, 10, H.TEXTE if ok else H.ROUGE, "w", False, w - 80 * s)
        else:
            lignes = [(self.pdf_ok, "PDF : signature integree (pyHanko)"),
                      (self.openssl_ok, "Autres fichiers : signature .p7s (OpenSSL)")]
            for k, (ok, texte) in enumerate(lignes):
                y = y0 + 156 * s + k * 26 * s
                if ok is None:
                    E.txt(30 * s, y, "...", 10, H.SOUS)
                else:
                    E.icone("check" if ok else "croix", 30 * s, y, 8 * s, H.VERT if ok else H.ORANGE, H.CARTE)
                E.txt(46 * s, y, texte if ok in (True, None) else texte + " : non disponible", 10, H.TEXTE if ok else H.ORANGE, "w")
        # 4. bouton
        if self.en_cours:
            E.bouton(10 * s, y0 + 204 * s, w - 10 * s, y0 + 274 * s, "Signature en cours...", None, H.VIOLET, "stylo", 17, False)
        else:
            E.bouton(10 * s, y0 + 204 * s, w - 10 * s, y0 + 274 * s, "SIGNER", self.signer, H.VIOLET, "stylo", 20)

    def choisir(self):
        chemins = filedialog.askopenfilenames(parent=self.racine, title="Fichiers a signer", initialdir=os.path.expanduser("~"))
        if chemins:
            self.fichiers = list(chemins)
            self.resultats = []
            self.E.rafraichir()

    def signer(self):
        if self.en_cours:
            return
        if not self.fichiers:
            self.choisir()
            if not self.fichiers:
                return
        module = self.cle[2]
        if module is None:
            self.resultats = [(False, "Module de la cle introuvable")]
            self.E.rafraichir()
            return
        pin = simpledialog.askstring("Code PIN", "Code PIN de la cle :", show="*", parent=self.racine)
        if not pin:
            return
        self.en_cours = True
        self.resultats = []
        self.E.rafraichir()
        fichiers = list(self.fichiers)

        def tache():
            res = []
            for chemin in fichiers:
                try:
                    if chemin.lower().endswith(".pdf"):
                        sortie = signer.signer_pdf(chemin, pin, module)
                    else:
                        sortie = signer.signer_detache(chemin, pin, module)
                    res.append((True, "Signe : " + os.path.basename(sortie)))
                except Exception as e:
                    res.append((False, "%s : %s" % (os.path.basename(chemin), str(e)[:90])))
            self.racine.after(0, self.fin_signature, res)
        threading.Thread(target=tache, daemon=True).start()

    def fin_signature(self, res):
        self.en_cours = False
        self.resultats = res
        self.E.rafraichir()


if __name__ == "__main__":
    racine = tk.Tk()
    Application(racine, [a for a in sys.argv[1:] if os.path.isfile(a)], H.taille_arg())
    racine.mainloop()
