"""core: static analysis engine + Claude tool-use loop (shared by CLI and GUI)."""
import hashlib, json, os, re
import anthropic, capstone, pefile
from elftools.elf.elffile import ELFFile

MODEL = os.environ.get("RE_AGENT_MODEL", "claude-sonnet-5-5")

SYSTEM = """You are a reverse-engineering analyst helping with authorized security work
(malware triage, CTFs, auditing software the user owns). You only have static-analysis tools.
Investigate step by step: file info -> sections -> imports -> strings -> disassembly.
Explain what the code does, flag suspicious behaviors (persistence, networking, crypto,
anti-debug, process injection) with evidence, and suggest defensive actions (detection
ideas, IOCs). Do not write weaponized exploits or malware."""


class Binary:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.kind, self.arch, self.mode = "raw", capstone.CS_ARCH_X86, capstone.CS_MODE_64
        self.entry_off, self.base = 0, 0
        self._parse()

    def _parse(self):
        if self.data[:2] == b"MZ":
            pe = pefile.PE(data=self.data)
            self.kind, self.pe = "PE", pe
            is64 = pe.FILE_HEADER.Machine == 0x8664
            self.mode = capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32
            self.base = pe.OPTIONAL_HEADER.ImageBase
            self.entry_off = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        elif self.data[:4] == b"\x7fELF":
            self.kind = "ELF"
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                self.elf_machine, self.elf_class = elf["e_machine"], elf.elfclass
                self.entry_va = elf["e_entry"]
                if elf["e_machine"] == "EM_ARM":
                    self.arch, self.mode = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
                elif elf["e_machine"] == "EM_AARCH64":
                    self.arch, self.mode = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
                else:
                    self.mode = capstone.CS_MODE_64 if elf.elfclass == 64 else capstone.CS_MODE_32
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= self.entry_va < seg["p_vaddr"] + seg["p_filesz"]:
                        self.entry_off = seg["p_offset"] + self.entry_va - seg["p_vaddr"]
                        self.base = seg["p_vaddr"] - seg["p_offset"]

    # ---- tools ----
    def file_info(self):
        return {"path": self.path, "size": len(self.data), "type": self.kind,
                "md5": hashlib.md5(self.data).hexdigest(),
                "sha256": hashlib.sha256(self.data).hexdigest(),
                "entry_file_offset": self.entry_off}

    def sections(self):
        if self.kind == "PE":
            return [{"name": s.Name.rstrip(b"\0").decode(errors="replace"),
                     "va": hex(s.VirtualAddress), "size": s.SizeOfRawData,
                     "entropy": round(s.get_entropy(), 2)} for s in self.pe.sections]
        if self.kind == "ELF":
            with open(self.path, "rb") as f:
                return [{"name": s.name, "addr": hex(s["sh_addr"]), "size": s["sh_size"]}
                        for s in ELFFile(f).iter_sections()]
        return []

    def imports(self):
        out = {}
        if self.kind == "PE" and hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for e in self.pe.DIRECTORY_ENTRY_IMPORT:
                out[e.dll.decode(errors="replace")] = [i.name.decode(errors="replace") for i in e.imports if i.name]
        elif self.kind == "ELF":
            with open(self.path, "rb") as f:
                sec = ELFFile(f).get_section_by_name(".dynsym")
                if sec:
                    out["dynsym"] = [s.name for s in sec.iter_symbols() if s.name]
        return out

    def strings(self, min_len=6, limit=200):
        found = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, self.data)
        wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, self.data)
        res = [s.decode() for s in found] + [s.decode("utf-16le", "ignore") for s in wide]
        return res[:limit]

    def disassemble(self, file_offset=None, count=40):
        off = self.entry_off if file_offset is None else int(file_offset)
        md = capstone.Cs(self.arch, self.mode)
        code = self.data[off:off + count * 15]
        return [f"{self.base + a if self.kind == 'ELF' else a + off:#x}: {m} {o}"
                for a, _, m, o in list(md.disasm_lite(code, 0))[:count]]


TOOLS = [
    {"name": "file_info", "description": "Hashes, size, format, entry point offset.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "sections", "description": "List sections with sizes/entropy (high entropy may mean packing).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "imports", "description": "List imported functions / dynamic symbols.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "strings", "description": "Extract printable ASCII/UTF-16 strings.",
     "input_schema": {"type": "object", "properties": {
         "min_len": {"type": "integer"}, "limit": {"type": "integer"}}}},
    {"name": "disassemble", "description": "Disassemble instructions at a file offset (defaults to entry point).",
     "input_schema": {"type": "object", "properties": {
         "file_offset": {"type": "integer"}, "count": {"type": "integer"}}}},
]


def run_tool(b, name, args):
    try:
        return json.dumps(getattr(b, name)(**args), default=str)[:20000]
    except Exception as e:
        return f"tool error: {e}"




def agent_turn(client, model, messages, binary, emit):
    """Run one user turn to completion. emit(kind, payload): kind in text|tool."""
    while True:
        r = client.messages.create(model=model, max_tokens=4096, system=SYSTEM,
                                   tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": r.content})
        for blk in r.content:
            if blk.type == "text":
                emit("text", blk.text)
        if r.stop_reason != "tool_use":
            return
        results = []
        for blk in r.content:
            if blk.type == "tool_use":
                emit("tool", f"{blk.name} {json.dumps(blk.input) if blk.input else ''}")
                results.append({"type": "tool_result", "tool_use_id": blk.id,
                                "content": run_tool(binary, blk.name, blk.input)})
        messages.append({"role": "user", "content": results})
