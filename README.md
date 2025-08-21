## CrackProof
  
CrackProof is a sophisticated password security analysis tool that evaluates password strength using advanced algorithms including entropy calculations, pattern detection, and real-time breach database checking. Built with cybersecurity professionals and security-conscious users in mind.

### Features
- Entropy estimation and character class analysis
- Detection of weak patterns (sequences, repeats, keyboard runs, dates, dictionary words)
- Optional Have I Been Pwned offline range query (k-anonymity)
- Dark-themed Tkinter UI with live scoring and tips

### Requirements
- Python 3.9+

Install dependencies:
```bash
pip install -r requirements.txt
```

### Run
```bash
python crackproof.py
```

### Tests
```bash
pytest -q
```

### Screenshots
Place UI screenshots in `CrackProof/screenshots/`.

### License
MIT — see `CrackProof/LICENSE`.

