"""CyberSuite — outils locaux de cybersécurité défensive."""
from __future__ import annotations

import ipaddress
import re
import socket
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse
from pathlib import Path

APP_VERSION = "1.0.0"
BG = "#101510"
PANEL = "#18221b"
GREEN = "#65e572"
TEXT = "#e5eee6"
MUTED = "#9aab9d"
WARN = "#ffc66d"
RED = "#ff7777"

COMMON_PORTS = (22, 80, 443, 445, 3389)


def password_report(secret: str) -> tuple[int, list[str]]:
    """Score local indicatif. Le secret n'est jamais écrit sur disque."""
    if not secret:
        return 0, ["Saisissez un texte de test (pas un mot de passe réutilisé)."]
    score = 0
    tips = []
    n = len(secret)
    score += min(40, n * 3)
    groups = sum(bool(re.search(p, secret)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    score += groups * 10
    if n < 12:
        tips.append("Utilisez une phrase de passe plus longue (12 caractères ou plus).")
    if groups < 3:
        tips.append("Variez les types de caractères ou choisissez plusieurs mots aléatoires.")
    if re.search(r"(.)\1{2,}", secret):
        tips.append("Évitez les répétitions de caractères.")
    if re.search(r"(?i)(password|azerty|qwerty|123456|admin)", secret):
        score -= 25
        tips.append("Évitez les suites et mots de passe très courants.")
    score = max(0, min(100, score))
    if not tips:
        tips.append("Bon résultat indicatif. Un gestionnaire de mots de passe et un mot de passe unique restent recommandés.")
    return score, tips


def analyze_logs(content: str) -> list[tuple[str, str]]:
    """Repère quelques motifs courants dans un fichier texte fourni localement."""
    rules = [
        ("Échecs d'authentification", re.compile(r"failed password|authentication failure|login failed|échec.*connexion", re.I)),
        ("Accès refusé", re.compile(r"access denied|permission denied|403 forbidden", re.I)),
        ("Activité administrateur", re.compile(r"sudo|administrator|admin login|privilège", re.I)),
        ("Erreurs serveur", re.compile(r"\b(500|502|503)\b|internal server error", re.I)),
        ("Entrée potentiellement suspecte", re.compile(r"\.\./|union\s+select|<script|powershell\s+-enc", re.I)),
    ]
    findings = []
    for number, line in enumerate(content.splitlines(), 1):
        for label, pattern in rules:
            if pattern.search(line):
                findings.append((str(number), f"{label} : {line[:240]}"))
                break
    return findings


def inspect_phishing(text: str) -> list[str]:
    """Heuristiques hors-ligne : n'ouvre jamais les liens détectés."""
    findings = []
    urls = re.findall(r"https?://[^\s<>\"']+", text, re.I)
    if not urls:
        findings.append("Aucune URL HTTP(S) détectée. Cela ne garantit pas que le message soit fiable.")
    for raw in urls[:30]:
        candidate = raw.rstrip(".,;:!?)\"]}")
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        reasons = []
        if not host:
            reasons.append("hôte illisible")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("nom de domaine internationalisé (punycode)")
        try:
            ipaddress.ip_address(host)
            reasons.append("adresse IP utilisée à la place d'un domaine")
        except ValueError:
            pass
        if "@" in parsed.netloc:
            reasons.append("caractère @ dans l'adresse")
        if host.count("-") >= 3:
            reasons.append("nom de domaine avec de nombreux tirets")
        if any(word in host for word in ("verify", "secure", "account", "login", "update", "support")):
            reasons.append("terme souvent utilisé dans les leurres")
        findings.append(f"{candidate} — " + (", ".join(reasons) if reasons else "aucun indice évident détecté"))
    lower = text.lower()
    if any(term in lower for term in ("urgence", "immédiatement", "compte suspendu", "confirmez votre mot de passe", "cadeau", "paiement refusé")):
        findings.append("Le texte utilise un langage pressant ou incitatif : vérifiez par un canal officiel.")
    if re.search(r"\b(mot de passe|code de vérification|coordonnées bancaires)\b", lower):
        findings.append("Le message semble demander des informations sensibles : ne les communiquez pas via un lien reçu.")
    return findings


def scan_private_host(target: str) -> list[str]:
    """Vérification TCP très limitée sur une IP privée explicitement fournie."""
    target = target.strip()
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError("Entrez une adresse IP numérique (pas un nom de domaine).")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValueError("Par sécurité, CyberScanner n'accepte que les IP privées, locales ou link-local.")
    results = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.45)
        try:
            address = (str(ip), port, 0, 0) if ip.version == 6 else (str(ip), port)
            status = sock.connect_ex(address)
            results.append(f"Port {port:5} : " + ("accessible" if status == 0 else "non accessible"))
        except OSError as exc:
            results.append(f"Port {port:5} : résultat indisponible ({exc.__class__.__name__})")
        finally:
            sock.close()
    return results


class CyberSuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"CyberSuite {APP_VERSION}")
        self.geometry("940x680")
        self.minsize(760, 560)
        self.configure(bg=BG)
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Title.TLabel", font=("Segoe UI", 23, "bold"), foreground=GREEN)
        style.configure("Sub.TLabel", foreground=MUTED)
        style.configure("TButton", background="#24442b", foreground=TEXT, padding=9, borderwidth=0)
        style.map("TButton", background=[("active", "#32613c")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT, padding=(15, 9))
        style.map("TNotebook.Tab", background=[("selected", "#24442b")], foreground=[("selected", GREEN)])
        style.configure("TEntry", fieldbackground="#0c110d", foreground=TEXT, insertcolor=TEXT)
        style.configure("TLabelFrame", background=PANEL, foreground=GREEN)
        style.configure("TLabelFrame.Label", background=PANEL, foreground=GREEN)
        style.configure("Horizontal.TProgressbar", troughcolor="#263329", background=GREEN)

    def _build(self):
        header = ttk.Frame(self, padding=(22, 18))
        header.pack(fill="x")
        ttk.Label(header, text="CYBERSUITE", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Boîte à outils de cybersécurité défensive • traitement local", style="Sub.TLabel").pack(anchor="w")
        ttk.Label(self, text="Utilisez ces outils uniquement sur vos systèmes, fichiers et comptes, ou avec autorisation explicite.", foreground=WARN, wraplength=880).pack(fill="x", padx=22, pady=(0, 12))

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self._scanner_tab(tabs)
        self._password_tab(tabs)
        self._logs_tab(tabs)
        self._phishing_tab(tabs)
        footer = ttk.Label(self, text="Aide à l'analyse uniquement — les résultats ne constituent pas un audit de sécurité complet.", style="Sub.TLabel")
        footer.pack(pady=(0, 10))

    def _new_tab(self, tabs, name):
        frame = ttk.Frame(tabs, padding=18)
        tabs.add(frame, text=name)
        return frame

    def _output(self, parent, height=13):
        box = tk.Text(parent, height=height, bg="#0b100c", fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", padx=12, pady=10)
        box.pack(fill="both", expand=True, pady=(12, 0))
        return box

    def _scanner_tab(self, tabs):
        tab = self._new_tab(tabs, "CyberScanner")
        ttk.Label(tab, text="Vérification réseau limitée", style="Title.TLabel").pack(anchor="w")
        ttk.Label(tab, text="Cible : adresse IP privée ou locale de ton propre réseau (ex. 192.168.1.1). Cinq ports courants sont testés, sans exploitation.", wraplength=820).pack(anchor="w", pady=8)
        line = ttk.Frame(tab)
        line.pack(fill="x", pady=8)
        self.scan_entry = ttk.Entry(line)
        self.scan_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.scan_entry.insert(0, "192.168.1.1")
        ttk.Button(line, text="Lancer le contrôle", command=self._run_scan).pack(side="right")
        self.scan_output = self._output(tab)

    def _run_scan(self):
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("end", "Contrôle limité en cours…\n")
        try:
            results = scan_private_host(self.scan_entry.get())
            self.scan_output.delete("1.0", "end")
            self.scan_output.insert("end", "Résultats (accessibilité TCP uniquement) :\n\n" + "\n".join(results))
            self.scan_output.insert("end", "\n\nUn port accessible n'indique pas à lui seul une vulnérabilité.")
        except ValueError as exc:
            self.scan_output.delete("1.0", "end")
            self.scan_output.insert("end", str(exc))

    def _password_tab(self, tabs):
        tab = self._new_tab(tabs, "PasswordChecker")
        ttk.Label(tab, text="Robustesse d'un mot de passe", style="Title.TLabel").pack(anchor="w")
        ttk.Label(tab, text="Test local indicatif. N'entrez jamais un mot de passe réel ou réutilisé ; essayez plutôt une phrase fictive.", wraplength=820).pack(anchor="w", pady=8)
        self.password_var = tk.StringVar()
        entry = ttk.Entry(tab, textvariable=self.password_var, show="•")
        entry.pack(fill="x", pady=8)
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(tab, text="Afficher le texte saisi", variable=self.show_password, command=lambda: entry.configure(show="" if self.show_password.get() else "•")).pack(anchor="w")
        ttk.Button(tab, text="Évaluer localement", command=self._check_password).pack(anchor="w", pady=12)
        self.score_label = ttk.Label(tab, text="Score : —", style="Title.TLabel")
        self.score_label.pack(anchor="w")
        self.score_bar = ttk.Progressbar(tab, maximum=100, mode="determinate")
        self.score_bar.pack(fill="x", pady=8)
        self.password_tips = ttk.Label(tab, text="Le contenu n'est ni enregistré ni envoyé.", wraplength=820)
        self.password_tips.pack(anchor="w", pady=8)

    def _check_password(self):
        score, tips = password_report(self.password_var.get())
        self.score_bar["value"] = score
        level = "faible" if score < 40 else "moyen" if score < 70 else "plutôt bon"
        self.score_label.configure(text=f"Score indicatif : {score}/100 — {level}")
        self.password_tips.configure(text="\n".join("• " + tip for tip in tips) + "\n\nCette estimation ne vérifie pas les fuites de données et ne remplace pas un gestionnaire de mots de passe.")
        self.password_var.set("")

    def _logs_tab(self, tabs):
        tab = self._new_tab(tabs, "LogAnalyzer")
        ttk.Label(tab, text="Analyse de journaux", style="Title.TLabel").pack(anchor="w")
        ttk.Label(tab, text="Choisis un fichier journal texte local. L'analyse recherche des motifs simples ; elle peut produire des faux positifs.", wraplength=820).pack(anchor="w", pady=8)
        ttk.Button(tab, text="Ouvrir un fichier journal", command=self._load_logs).pack(anchor="w", pady=6)
        self.log_output = self._output(tab)

    def _load_logs(self):
        path = filedialog.askopenfilename(title="Choisir un journal", filetypes=[("Fichiers texte", "*.log *.txt *.csv"), ("Tous les fichiers", "*.*")])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            findings = analyze_logs(content)
            self.log_output.delete("1.0", "end")
            self.log_output.insert("end", f"Fichier : {Path(path).name}\nLignes analysées : {len(content.splitlines())}\nÉléments repérés : {len(findings)}\n\n")
            if findings:
                for line, detail in findings[:500]:
                    self.log_output.insert("end", f"Ligne {line} — {detail}\n")
            else:
                self.log_output.insert("end", "Aucun motif connu détecté. Cela ne garantit pas l'absence d'incident.")
        except OSError as exc:
            messagebox.showerror("Lecture impossible", str(exc))

    def _phishing_tab(self, tabs):
        tab = self._new_tab(tabs, "PhishingDetector")
        ttk.Label(tab, text="Détection d'indices de phishing", style="Title.TLabel").pack(anchor="w")
        ttk.Label(tab, text="Colle le texte d'un message ou une URL. Aucun lien ne sera ouvert ni contacté.", wraplength=820).pack(anchor="w", pady=8)
        self.phishing_input = tk.Text(tab, height=7, bg="#0b100c", fg=TEXT, insertbackground=TEXT, relief="flat", padx=10, pady=8, wrap="word")
        self.phishing_input.pack(fill="x", pady=8)
        ttk.Button(tab, text="Analyser le texte", command=self._check_phishing).pack(anchor="w", pady=5)
        self.phishing_output = self._output(tab, height=10)

    def _check_phishing(self):
        text = self.phishing_input.get("1.0", "end").strip()
        findings = inspect_phishing(text)
        self.phishing_output.delete("1.0", "end")
        self.phishing_output.insert("end", "\n".join("• " + item for item in findings))
        self.phishing_output.insert("end", "\n\nEn cas de doute, ne clique pas. Vérifie le site en saisissant toi-même son adresse officielle.")

if __name__ == "__main__":
    CyberSuiteApp().mainloop()
