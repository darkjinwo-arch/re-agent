#!/usr/bin/env python3
"""CLI version. For the desktop UI run: python app.py"""
import argparse, sys, anthropic
from core import Binary, agent_turn, MODEL

ap = argparse.ArgumentParser(description="Static RE agent (authorized use only)")
ap.add_argument("binary")
ap.add_argument("-q", "--question", default="Give me a full triage report of this binary.")
ap.add_argument("-i", "--interactive", action="store_true")
a = ap.parse_args()
b, client = Binary(a.binary), anthropic.Anthropic()
msgs = [{"role": "user", "content": a.question}]
emit = lambda k, p: print(p if k == "text" else f"[tool] {p}", file=sys.stdout if k == "text" else sys.stderr)
while True:
    agent_turn(client, MODEL, msgs, b, emit)
    if not a.interactive: break
    q = input("\nyou> ").strip()
    if q in ("", "exit", "quit"): break
    msgs.append({"role": "user", "content": q})
