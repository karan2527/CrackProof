import re
import math
import hashlib
import requests
from tkinter import Tk, StringVar, ttk, IntVar, messagebox, Checkbutton

# ---------------------------
# Core password analysis
# ---------------------------

USER_AGENT = "EntropyX/1.0 (Password Strength Checker; https://example.local)"  # set your URL/email if you have one

COMMON_KEYBOARD_RUNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()"
]

COMMON_WORDS = {
    "password", "pass", "admin", "login", "letmein", "welcome", "qwerty",
    "iloveyou", "dragon", "monkey", "football", "baseball", "abc123", "111111",
    "secret", "user", "test"
}

LEET_MAP = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","$":"s","@":"a"})

def char_pool_size(pw: str) -> int:
    pools = [
        any(c.islower() for c in pw) * 26,
        any(c.isupper() for c in pw) * 26,
        any(c.isdigit() for c in pw) * 10,
    ]
    # Approx set of printable symbols used commonly
    symbols = set("!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\")
    pools.append((any(c in symbols for c in pw)) * len(symbols))
    # Include other unicode as 0 (ignored) for simplicity
    return sum(pools)

def estimate_entropy_bits(pw: str) -> float:
    if not pw:
        return 0.0
    pool = max(char_pool_size(pw), 1)
    return len(pw) * math.log2(pool)

def has_sequential_runs(pw: str, min_run: int = 4) -> bool:
    # Check ascending/descending alpha or digit sequences
    def is_seq(a, b): return (ord(b) - ord(a)) in (1, -1)
    run = 1
    for i in range(1, len(pw)):
        if is_seq(pw[i-1].lower(), pw[i].lower()):
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False

def has_repeated_patterns(pw: str, min_len: int = 2, repeats: int = 2) -> bool:
    # e.g., "abab", "123123", "aaaa"
    for L in range(min_len, max(min_len+1, len(pw)//repeats+1)):
        chunk = pw[:L]
        if chunk * repeats in pw:
            return True
    # long same-char runs
    return bool(re.search(r"(.)\1{3,}", pw))

def has_keyboard_runs(pw: str, min_len: int = 4) -> bool:
    low = pw.lower()
    for run in COMMON_KEYBOARD_RUNS:
        if any(run[i:i+min_len] in low for i in range(0, len(run)-min_len+1)):
            return True
        if any(run[i:i+min_len][::-1] in low for i in range(0, len(run)-min_len+1)):
            return True
    return False

def looks_like_date(pw: str) -> bool:
    # 2024, 1999, 2025-08-18, 18/08/2025, 08182025, etc.
    patterns = [
        r"\b(19|20)\d{2}\b",
        r"\b(0?[1-9]|1[0-2])[-/\.]((0?[1-9])|([12]\d)|(3[01]))[-/\.]((19|20)\d{2})\b",
        r"\b((0?[1-9])|([12]\d)|(3[01]))[-/\.]((0?[1-9])|(1[0-2]))[-/\.]((19|20)\d{2})\b",
        r"\b(19|20)\d{2}[-/\.]((0?[1-9])|(1[0-2]))[-/\.]((0?[1-9])|([12]\d)|(3[01]))\b",
        r"\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}\b"
    ]
    s = pw
    return any(re.search(p, s) for p in patterns)

def dictionary_match(pw: str) -> bool:
    low = pw.lower()
    if any(w in low for w in COMMON_WORDS):
        return True
    # leetspeak normalized
    norm = low.translate(LEET_MAP)
    return any(w in norm for w in COMMON_WORDS)

def hibp_pwned_count(pw: str, timeout=6) -> int:
    """
    k-anonymity: send only SHA1(prefix 5 chars), match suffix locally.
    Returns number of breaches the password hash appears in, else 0.
    """
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return 0
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                return int(parts[1].strip())
        return 0
    except requests.RequestException:
        return 0

def score_password(pw: str, check_breach=True) -> dict:
    length = len(pw)
    entropy = estimate_entropy_bits(pw)
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\"
            for c in pw)
    ])

    penalties = []
    if length < 8: penalties.append("Too short (<8).")
    if has_sequential_runs(pw): penalties.append("Sequential characters.")
    if has_repeated_patterns(pw): penalties.append("Repeated patterns or runs.")
    if has_keyboard_runs(pw): penalties.append("Keyboard sequence.")
    if looks_like_date(pw): penalties.append("Looks like a date.")
    if dictionary_match(pw): penalties.append("Contains common words.")

    pwned = hibp_pwned_count(pw) if check_breach else 0
    if pwned > 0:
        penalties.append(f"Found in breaches ({pwned} times).")

    # Base score from entropy & length
    base = 0
    if entropy >= 80: base = 4
    elif entropy >= 60: base = 3
    elif entropy >= 40: base = 2
    elif entropy >= 28: base = 1
    else: base = 0

    # Adjust by character classes
    base += max(0, classes - 1)  # +0..+3

    # Penalty hits
    base -= min(len(penalties), 4)

    # Clamp 0..10
    score = max(0, min(10, base))

    label = (
        "Very Weak" if score <= 2 else
        "Weak" if score <= 4 else
        "Moderate" if score <= 6 else
        "Strong" if score <= 8 else
        "Excellent"
    )

    tips = []
    if length < 12: tips.append("Use 12–16+ characters.")
    if classes < 3: tips.append("Mix lower/upper/digits/symbols.")
    if dictionary_match(pw): tips.append("Avoid dictionary words or names.")
    if has_sequential_runs(pw) or has_keyboard_runs(pw):
        tips.append("Avoid sequences like 1234, qwerty, abcd.")
    if has_repeated_patterns(pw):
        tips.append("Avoid repeats (e.g., abab, 1111).")
    if looks_like_date(pw):
        tips.append("Avoid dates or personal info.")
    if pwned > 0:
        tips.append("This password is breached; change it everywhere.")

    return {
        "length": length,
        "entropy_bits": round(entropy, 2),
        "classes": classes,
        "pwned_count": pwned,
        "penalties": penalties,
        "score": score,
        "label": label,
        "tips": tips
    }

# ---------------------------
# Simple Tkinter GUI
# ---------------------------

class EntropyXApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EntropyX — Password Strength Checker")
        self.root.geometry("640x300")

        self.show_breach = IntVar(value=1)
        self.pw_var = StringVar()
        self.result_var = StringVar(value="Type a password…")

        ttk.Label(root, text="Enter Password:").pack(pady=(16, 4))
        self.entry = ttk.Entry(root, textvariable=self.pw_var, show="*", width=50)
        self.entry.pack()
        self.entry.bind("<KeyRelease>", self.on_change)

        self.progress = ttk.Progressbar(root, orient="horizontal",
                                        length=320, mode="determinate", maximum=10)
        self.progress.pack(pady=10)

        self.label = ttk.Label(root, textvariable=self.result_var, wraplength=560, justify="left")
        self.label.pack(pady=4)

        self.chk = Checkbutton(root, text="Check breaches (Have I Been Pwned)",
                    variable=self.show_breach, command=self.on_change)
        self.chk.pack(pady=(6, 2))

        ttk.Button(root, text="Copy Safety Tips", command=self.copy_tips).pack(pady=6)

        # Apply dark theme styling for ttk widgets
        try:
            style = ttk.Style()
            if "clam" in style.theme_names():
                style.theme_use("clam")
            self.dark_bg = "#121212"
            self.dark_fg = "#E0E0E0"
            self.field_bg = "#1E1E1E"
            self.accent = "#4CAF50"
            self.root.configure(bg=self.dark_bg)
            style.configure(".", background=self.dark_bg, foreground=self.dark_fg)
            style.configure("TLabel", background=self.dark_bg, foreground=self.dark_fg)
            style.configure("TCheckbutton", background=self.dark_bg, foreground=self.dark_fg)
            style.configure("TButton", background=self.field_bg, foreground=self.dark_fg)
            style.map("TButton", background=[("active", "#2A2A2A")])
            style.configure("TEntry", fieldbackground=self.field_bg, foreground=self.dark_fg)
            style.map("TEntry", fieldbackground=[("!disabled", self.field_bg)])
            style.configure("TProgressbar", background=self.accent, troughcolor="#2C2C2C")

            # Style classic Tk Checkbutton to show a tick and match dark theme
            try:
                self.chk.configure(
                    bg=self.dark_bg,
                    fg=self.dark_fg,
                    activebackground=self.dark_bg,
                    activeforeground=self.dark_fg,
                    selectcolor="#2C2C2C",
                    highlightthickness=0
                )
            except Exception:
                pass
        except Exception:
            pass

    def on_change(self, event=None):
        pw = self.pw_var.get()
        if not pw:
            self.progress["value"] = 0
            self.result_var.set("Type a password…")
            return
        res = score_password(pw, check_breach=bool(self.show_breach.get()))
        self.progress["value"] = res["score"]
        info = (
            f"Strength: {res['label']} ({res['score']}/10)\n"
            f"Length: {res['length']}  |  Entropy: {res['entropy_bits']} bits  |  Classes: {res['classes']}\n"
            f"Breach hits: {res['pwned_count']}\n"
            f"Flags: {', '.join(res['penalties']) if res['penalties'] else 'None'}\n"
            f"Tips: {', '.join(res['tips']) if res['tips'] else 'Looks good!'}"
        )
        self.result_var.set(info)

    def copy_tips(self):
        pw = self.pw_var.get()
        res = score_password(pw, check_breach=bool(self.show_breach.get())) if pw else {"tips": []}
        tips_text = "\n".join(res.get("tips", [])) or "Enter a password first."
        self.root.clipboard_clear()
        self.root.clipboard_append(tips_text)
        messagebox.showinfo("EntropyX", "Tips copied to clipboard.")

def main():
    root = Tk()
    EntropyXApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

