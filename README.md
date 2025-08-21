## CrackProof

EntropyX-powered password strength checker with entropy, pattern analysis, and Have I Been Pwned breach lookup. Ships with a simple Tkinter GUI.

### Features
- Entropy estimation and character class analysis
- Detection of weak patterns (sequences, repeats, keyboard runs, dates, dictionary words)
- Optional Have I Been Pwned offline range query (k-anonymity)
- Dark-themed Tkinter UI with live scoring and tips

### Requirements
- Python 3.9+

Install dependencies:
```bash
pip install -r CrackProof/requirements.txt
```

### Run
```bash
python CrackProof/crackproof.py
```

### Tests
```bash
pytest -q
```

### Screenshots
Place UI screenshots in `CrackProof/screenshots/`.

### License
MIT — see `CrackProof/LICENSE`.

