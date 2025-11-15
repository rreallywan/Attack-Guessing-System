"""
cyber_attack_guesser_gui.py

A simple Tkinter GUI wrapper for the simplified Cyber Attack Guesser.

Features:
- Presents 12 basic yes/no questions as toggle buttons (Yes/No/Unknown).
- "Analyze" button finds the best-matching attack and displays mitigation.
- "Teach" button opens a dialog to add a new attack (answers + mitigation lines).
- Knowledge is persisted to `cyber_kb.json` in the same directory.
- Defensive/educational only.

Run: python cyber_attack_guesser_gui.py
"""

import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

KB_PATH = "cyber_kb.json"

# The 12 simplified questions and default KB (same as CLI app)
QUESTIONS = {
    "email_vector": "Did the attack start from an email?",
    "user_clicked": "Did the user click a link or open a file?",
    "credentials_involved": "Was a login page or credentials involved?",
    "service_down": "Is the website or service unavailable?",
    "ransom_note": "Is there file encryption or a ransom note?",
    "web_target": "Is this targeting a website or web application?",
    "failed_logins": "Were many failed login attempts recorded?",
    "high_traffic": "Is there abnormal or high network traffic?",
    "unexpected_programs": "Was an unwanted program downloaded or executed?",
    "data_transfer": "Was sensitive data accessed/transferred out?",
    "browser_script": "Did unexpected scripts execute in the browser?",
    "spoofed_sender": "Was the sender/source suspicious or spoofed?"
}

DEFAULT_KB = {
    "Phishing": {
        "attributes": {
            "email_vector": True,
            "user_clicked": True,
            "credentials_involved": True,
            "spoofed_sender": True
        },
        "mitigation": [
            "Do not click unfamiliar links or attachments.",
            "Report email and block sender.",
            "Enable MFA to limit credential theft impact."
        ]
    },
    "Spearphishing": {
        "attributes": {
            "email_vector": True,
            "user_clicked": True,
            "credentials_involved": True,
            "spoofed_sender": True
        },
        "mitigation": [
            "Verify unusual requests through another channel.",
            "Educate high-risk staff about targeted attacks.",
            "Review email headers for spoofing."
        ]
    },
    "Ransomware": {
        "attributes": {
            "ransom_note": True,
            "unexpected_programs": True
        },
        "mitigation": [
            "Isolate infected machines immediately.",
            "Do not pay ransom; consult legal/security.",
            "Restore from clean backups."
        ]
    },
    "DDoS Attack": {
        "attributes": {
            "service_down": True,
            "high_traffic": True
        },
        "mitigation": [
            "Enable DDoS protection or CDN filtering.",
            "Rate-limit suspicious traffic.",
            "Work with hosting provider for mitigation."
        ]
    },
    "SQL Injection": {
        "attributes": {
            "web_target": True,
            "credentials_involved": False,
            "browser_script": False
        },
        "mitigation": [
            "Use parameterized database queries.",
            "Deploy a Web Application Firewall (WAF).",
            "Review logs and patch vulnerable code."
        ]
    },
    "XSS (Cross-Site Scripting)": {
        "attributes": {
            "web_target": True,
            "browser_script": True
        },
        "mitigation": [
            "Sanitize user input and output.",
            "Enable Content Security Policy (CSP).",
            "Patch vulnerable pages."
        ]
    },
    "Brute Force Attack": {
        "attributes": {
            "failed_logins": True,
            "credentials_involved": True
        },
        "mitigation": [
            "Apply rate-limiting on login attempts.",
            "Enable MFA.",
            "Increase account lockout sensitivity."
        ]
    },
    "Malware Infection": {
        "attributes": {
            "unexpected_programs": True,
            "user_clicked": True
        },
        "mitigation": [
            "Isolate infected endpoint.",
            "Perform malware scan and remove persistence.",
            "Check for additional infections on network."
        ]
    },
    "Data Exfiltration": {
        "attributes": {
            "data_transfer": True,
            "high_traffic": True
        },
        "mitigation": [
            "Identify affected accounts and rotate credentials.",
            "Block suspicious outbound traffic.",
            "Notify affected parties if needed."
        ]
    },
    "Credential Theft": {
        "attributes": {
            "credentials_involved": True,
            "spoofed_sender": True
        },
        "mitigation": [
            "Force password resets.",
            "Enable MFA to prevent unauthorized access.",
            "Review account activity logs for misuse."
        ]
    }
}

# -------------------------------
# KB load/save
# -------------------------------

def load_kb():
    if os.path.exists(KB_PATH):
        try:
            with open(KB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            messagebox.showwarning("KB Load", "Could not read knowledge base file. Loading defaults.")
    return DEFAULT_KB.copy()


def save_kb(kb):
    with open(KB_PATH, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=2)

# -------------------------------
# Matching logic
# -------------------------------

def find_best_match(kb, answers):
    best = None
    best_score = -1
    for attack, data in kb.items():
        attrs = data.get("attributes", {})
        score = 0
        for k, v in attrs.items():
            # count a match if answers has same boolean value
            if k in answers and answers[k] == v:
                score += 1
        if score > best_score:
            best_score = score
            best = attack
    return best, best_score

# -------------------------------
# GUI Application
# -------------------------------

class CyberGuesserApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Attack Identifier — GUI")
        self.geometry("720x560")
        self.resizable(False, False)
        self.kb = load_kb()
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Header
        ttk.Label(frm, text="Cyber Attack Expert System", font=(None, 16, "bold")).pack(anchor=tk.W)
        ttk.Label(frm, text="Answer the 12 basic questions (Yes/No/Unknown) then click Analyze.", foreground="#333").pack(anchor=tk.W, pady=(0,10))

        # Questions grid
        qframe = ttk.Frame(frm)
        qframe.pack(fill=tk.BOTH, expand=False)

        self.answer_vars = {}
        row = 0
        col = 0
        for i, (key, qtext) in enumerate(QUESTIONS.items()):
            card = ttk.LabelFrame(qframe, text=f"{i+1}. {qtext}", padding=6)
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            var = tk.StringVar(value="unknown")
            self.answer_vars[key] = var

            rb_yes = ttk.Radiobutton(card, text="Yes", variable=var, value="yes")
            rb_no = ttk.Radiobutton(card, text="No", variable=var, value="no")
            rb_unknown = ttk.Radiobutton(card, text="Unknown", variable=var, value="unknown")
            rb_yes.pack(side=tk.LEFT, padx=4)
            rb_no.pack(side=tk.LEFT, padx=4)
            rb_unknown.pack(side=tk.LEFT, padx=4)

            col += 1
            if col >= 2:
                col = 0
                row += 1

        # Action buttons
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=(12,0))

        analyze_btn = ttk.Button(btn_frame, text="Analyze", command=self.on_analyze)
        analyze_btn.pack(side=tk.LEFT, padx=6)

        teach_btn = ttk.Button(btn_frame, text="Teach New Attack", command=self.on_teach)
        teach_btn.pack(side=tk.LEFT, padx=6)

        reset_btn = ttk.Button(btn_frame, text="Reset Answers", command=self.reset_answers)
        reset_btn.pack(side=tk.LEFT, padx=6)

        save_btn = ttk.Button(btn_frame, text="Save KB", command=self.on_save)
        save_btn.pack(side=tk.RIGHT, padx=6)

        # Result / mitigation text
        self.result_text = tk.Text(frm, height=10, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(10,0))
        self.result_text.insert(tk.END, "Ready — provide answers then click Analyze.\n")
        self.result_text.config(state=tk.DISABLED)

    def reset_answers(self):
        for v in self.answer_vars.values():
            v.set("unknown")
        self.write_result("Answers reset.")

    def collect_answers(self):
        answers = {}
        for k, var in self.answer_vars.items():
            val = var.get()
            if val == "yes":
                answers[k] = True
            elif val == "no":
                answers[k] = False
            else:
                # Unknown -> leave out to avoid penalizing
                pass
        return answers

    def write_result(self, msg):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, msg)
        self.result_text.config(state=tk.DISABLED)

    def on_analyze(self):
        answers = self.collect_answers()
        if not answers:
            if not messagebox.askyesno("Confirm", "You provided no answers. Analyze anyway? This may be inaccurate."):
                return
        match, score = find_best_match(self.kb, answers)
        if match is None:
            self.write_result("No match found in KB.")
            return
        # display result and mitigation
        msg = f"Likely attack: {match}\nMatch score: {score}\n\nMitigation:\n"
        mitig = self.kb.get(match, {}).get("mitigation", [])
        if mitig:
            for step in mitig:
                msg += f"- {step}\n"
        else:
            msg += "(No mitigation stored for this attack.)\n"
        self.write_result(msg)

        # Ask user to confirm correctness and offer teaching if wrong
        ok = messagebox.askyesno("Confirm", f"Is the identified attack '{match}' correct?")
        if not ok:
            teach = messagebox.askyesno("Teach", "Would you like to teach the correct attack now?")
            if teach:
                self.on_teach()

    def on_teach(self):
        name = simpledialog.askstring("New Attack", "Enter the name of the new attack:")
        if not name:
            return
        # collect attributes by prompting same questions (simple dialog)
        new_attrs = {}
        for k, q in QUESTIONS.items():
            ans = messagebox.askyesno("Attribute", q + "\n(Yes = True, No = False). Click Cancel to set Unknown.")
            # messagebox.askyesno returns True/False; no cancel option in standard askyesno
            # to allow Unknown, we'll instead ask an input dialog
            # But to keep simple, we treat Cancel as No via a secondary dialog below
            new_attrs[k] = ans
        # collect mitigation lines
        mitig_lines = []
        messagebox.showinfo("Mitigation", "You will now enter mitigation lines. Press OK and then enter lines one by one. Enter a blank line to finish.")
        while True:
            line = simpledialog.askstring("Mitigation line", "Enter mitigation/advice line (leave blank to finish):")
            if line is None or line.strip() == "":
                break
            mitig_lines.append(line.strip())
        self.kb[name] = {"attributes": new_attrs, "mitigation": mitig_lines}
        save_kb(self.kb)
        messagebox.showinfo("Saved", f"New attack '{name}' saved to knowledge base.")
        self.write_result(f"Learned new attack: {name}\nMitigation saved.")

    def on_save(self):
        save_kb(self.kb)
        messagebox.showinfo("Saved", "Knowledge base saved to disk.")


if __name__ == "__main__":
    app = CyberGuesserApp()
    app.mainloop()
