"""RE Agent - desktop UI (CustomTkinter). Run: python app.py"""
import json, os, queue, threading
from pathlib import Path
from tkinter import filedialog, messagebox
import customtkinter as ctk
import anthropic
from core import Binary, agent_turn, MODEL

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG, PANEL, CARD = "#0b1020", "#111831", "#172042"
ACCENT, ACCENT_HOVER, GREEN, AMBER, MUTED = "#22d3ee", "#06b6d4", "#4ade80", "#fbbf24", "#8b97b8"
CFG = Path.home() / ".re_agent.json"


def load_cfg():
    try:
        return json.loads(CFG.read_text())
    except Exception:
        return {}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RE Agent  -  AI Reverse Engineering Workbench")
        self.geometry("1240x780")
        self.minsize(1000, 640)
        self.configure(fg_color=BG)
        self.bin, self.messages, self.busy = None, [], False
        self.q = queue.Queue()
        self.mono = ctk.CTkFont(family="Consolas", size=13)
        self.cfg = load_cfg()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self.after(80, self._poll)

    # ---------------- UI ----------------
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=PANEL)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        ctk.CTkLabel(sb, text="RE Agent", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=ACCENT).pack(anchor="w", padx=22, pady=(26, 0))
        ctk.CTkLabel(sb, text="Static analysis  +  Claude", text_color=MUTED).pack(anchor="w", padx=22)
        ctk.CTkButton(sb, text="Open binary", height=42, corner_radius=10, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, text_color="#04111a",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.open_file).pack(fill="x", padx=22, pady=(24, 10))
        self.file_card = ctk.CTkLabel(sb, text="No file loaded", justify="left", anchor="w",
                                      wraplength=230, fg_color=CARD, corner_radius=10,
                                      text_color=MUTED, padx=12, pady=12)
        self.file_card.pack(fill="x", padx=22)

        ctk.CTkLabel(sb, text="ANTHROPIC API KEY", text_color=MUTED,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=22, pady=(26, 4))
        self.key = ctk.CTkEntry(sb, show="*", height=36, fg_color=CARD, border_width=0)
        self.key.pack(fill="x", padx=22)
        self.key.insert(0, os.environ.get("ANTHROPIC_API_KEY", self.cfg.get("key", "")))
        ctk.CTkLabel(sb, text="MODEL", text_color=MUTED,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=22, pady=(14, 4))
        self.model = ctk.CTkEntry(sb, height=36, fg_color=CARD, border_width=0)
        self.model.pack(fill="x", padx=22)
        self.model.insert(0, self.cfg.get("model", MODEL))
        ctk.CTkButton(sb, text="Save settings", height=32, fg_color=CARD, hover_color="#223063",
                      command=self.save_cfg).pack(fill="x", padx=22, pady=(12, 0))
        ctk.CTkLabel(sb, text="Static analysis only - the file is never executed.\n"
                              "Use on files you own or are authorized to analyze.",
                     text_color=MUTED, justify="left", wraplength=230,
                     font=ctk.CTkFont(size=11)).pack(side="bottom", anchor="w", padx=22, pady=20)

    def _textbox(self, parent):
        t = ctk.CTkTextbox(parent, font=self.mono, fg_color=PANEL, corner_radius=10,
                           text_color="#d6def5", wrap="none")
        t.configure(state="disabled")
        return t

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=18, pady=18)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)
        self.tabs = ctk.CTkTabview(main, fg_color=BG, segmented_button_selected_color=ACCENT,
                                   segmented_button_selected_hover_color=ACCENT_HOVER,
                                   segmented_button_unselected_color=PANEL,
                                   text_color="#04111a")
        self.tabs.grid(row=0, column=0, sticky="nsew")
        self.views = {}
        for name in ["AI Analyst", "Overview", "Sections", "Imports", "Strings", "Disassembly"]:
            tab = self.tabs.add(name)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0 if name != "Disassembly" else 1, weight=1)
            if name == "AI Analyst":
                self._build_chat(tab)
            elif name == "Disassembly":
                bar = ctk.CTkFrame(tab, fg_color="transparent")
                bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
                self.off = ctk.CTkEntry(bar, width=160, placeholder_text="file offset (int)",
                                        fg_color=CARD, border_width=0)
                self.off.pack(side="left")
                ctk.CTkButton(bar, text="Disassemble", width=120, fg_color=ACCENT,
                              hover_color=ACCENT_HOVER, text_color="#04111a",
                              command=self.do_disasm).pack(side="left", padx=8)
                self.views[name] = self._textbox(tab)
                self.views[name].grid(row=1, column=0, sticky="nsew")
            else:
                self.views[name] = self._textbox(tab)
                self.views[name].grid(row=0, column=0, sticky="nsew")

    def _build_chat(self, tab):
        tab.grid_rowconfigure(0, weight=1)
        self.chat = ctk.CTkTextbox(tab, font=ctk.CTkFont(size=14), fg_color=PANEL,
                                   corner_radius=10, wrap="word", text_color="#d6def5")
        self.chat.grid(row=0, column=0, sticky="nsew")
        self.chat.tag_config("you", foreground=ACCENT)
        self.chat.tag_config("tool", foreground=AMBER)
        self.chat.tag_config("ai", foreground="#d6def5")
        self.chat.tag_config("err", foreground="#f87171")
        self.chat.configure(state="disabled")
        self._chat_write("RE Agent ready. Open a binary, then click 'Full triage' or ask a question.\n\n", "tool")
        quick = ctk.CTkFrame(tab, fg_color="transparent")
        quick.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        for label, q in [("Full triage", "Give me a full triage report of this binary."),
                         ("Suspicious behavior?", "Does this binary show suspicious or malicious behavior? Show evidence."),
                         ("Explain entry point", "Disassemble the entry point and explain what it does."),
                         ("Is it packed?", "Check whether this binary looks packed or obfuscated.")]:
            ctk.CTkButton(quick, text=label, height=30, corner_radius=15, fg_color=CARD,
                          hover_color="#223063", command=lambda q=q: self.ask(q)).pack(side="left", padx=(0, 8))
        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        row.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(row, height=44, placeholder_text="Ask about the binary...",
                                  fg_color=CARD, border_width=0, corner_radius=10)
        self.entry.grid(row=0, column=0, sticky="ew")
        self.entry.bind("<Return>", lambda e: self.ask(self.entry.get()))
        self.send_btn = ctk.CTkButton(row, text="Send", width=100, height=44, fg_color=ACCENT,
                                      hover_color=ACCENT_HOVER, text_color="#04111a",
                                      command=lambda: self.ask(self.entry.get()))
        self.send_btn.grid(row=0, column=1, padx=(8, 0))

    # ---------------- helpers ----------------
    def _set(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _chat_write(self, text, tag="ai"):
        self.chat.configure(state="normal")
        self.chat.insert("end", text, tag)
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def save_cfg(self):
        CFG.write_text(json.dumps({"key": self.key.get().strip(), "model": self.model.get().strip()}))
        messagebox.showinfo("Saved", f"Settings saved to {CFG}")

    # ---------------- actions ----------------
    def open_file(self):
        path = filedialog.askopenfilename(title="Select binary (.exe .dll .elf .so ...)")
        if not path:
            return
        try:
            self.bin = Binary(path)
        except Exception as e:
            messagebox.showerror("Cannot parse file", str(e))
            return
        self.messages = []
        info = self.bin.file_info()
        self.file_card.configure(text_color="#d6def5",
            text=f"{Path(path).name}\n{info['type']}  -  {info['size']:,} bytes\nSHA256\n{info['sha256'][:32]}...")
        self._set(self.views["Overview"], json.dumps(info, indent=2))
        secs = self.bin.sections()
        self._set(self.views["Sections"], "\n".join(
            "  ".join(f"{k}={v}" for k, v in s.items()) for s in secs) or "No section data")
        imps = self.bin.imports()
        self._set(self.views["Imports"], "\n\n".join(
            f"[{lib}]\n  " + "\n  ".join(fn) for lib, fn in imps.items()) or "No imports found")
        self._set(self.views["Strings"], "\n".join(self.bin.strings(limit=3000)))
        self.do_disasm(entry=True)
        self._chat_write(f"\nLoaded {Path(path).name}\n\n", "tool")

    def do_disasm(self, entry=False):
        if not self.bin:
            return
        try:
            off = None if entry or not self.off.get().strip() else int(self.off.get(), 0)
            self._set(self.views["Disassembly"], "\n".join(self.bin.disassemble(off, 120)))
        except Exception as e:
            messagebox.showerror("Disassembly error", str(e))

    def ask(self, text):
        text = text.strip()
        if not text or self.busy:
            return
        if not self.bin:
            return messagebox.showwarning("No binary", "Open a binary first.")
        key = self.key.get().strip()
        if not key:
            return messagebox.showwarning("API key", "Enter your Anthropic API key in the sidebar.")
        self.entry.delete(0, "end")
        self.tabs.set("AI Analyst")
        self._chat_write(f"You: {text}\n\n", "you")
        self.messages.append({"role": "user", "content": text})
        self.busy = True
        self.send_btn.configure(state="disabled", text="Thinking...")
        threading.Thread(target=self._worker, args=(key, self.model.get().strip() or MODEL),
                         daemon=True).start()

    def _worker(self, key, model):
        try:
            agent_turn(anthropic.Anthropic(api_key=key), model, self.messages, self.bin,
                       lambda k, p: self.q.put((k, p)))
        except Exception as e:
            self.q.put(("err", str(e)))
        self.q.put(("done", None))

    def _poll(self):
        try:
            while True:
                kind, p = self.q.get_nowait()
                if kind == "text":
                    self._chat_write(p + "\n\n", "ai")
                elif kind == "tool":
                    self._chat_write(f"  > tool: {p}\n", "tool")
                elif kind == "err":
                    self._chat_write(f"Error: {p}\n\n", "err")
                elif kind == "done":
                    self.busy = False
                    self.send_btn.configure(state="normal", text="Send")
        except queue.Empty:
            pass
        self.after(80, self._poll)


if __name__ == "__main__":
    App().mainloop()
