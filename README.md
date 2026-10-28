# RE Agent

Desktop AI reverse-engineering workbench. Static analysis (PE/ELF parsing, strings, imports,
Capstone disassembly) + Claude as an analyst. **The target file is never executed.**
Authorized use only: CTFs, lab malware triage, software you own.

## Run
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Paste your Anthropic API key in the sidebar -> Open binary -> "Full triage".

CLI: `python agent.py file.exe -i`

## Host on GitHub
```bash
./push_to_github.sh https://github.com/<your-username>/re-agent.git
git tag v1.0.0 && git push origin v1.0.0   # builds Windows/Mac/Linux apps via Actions
```
Download the built apps from the repo's **Actions -> Artifacts**.
