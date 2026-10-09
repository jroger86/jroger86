"""
Cybersecurity / CTF agent powered by Claude with tool use.
Provides concrete utility functions (decode, hash ID, flag search, Caesar brute-force,
encoding detection) that Claude calls as part of an agentic loop.
"""

import base64
import codecs
import re
from urllib.parse import unquote

import anthropic

client = anthropic.Anthropic()
MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = """You are an expert cybersecurity and CTF (Capture The Flag) assistant.
You specialize in:
- Decoding and encoding challenges (base64, hex, ROT13, binary, URL, etc.)
- Identifying hash types and suggesting cracking strategies
- CTF cryptography, web, forensics, reverse engineering, and steganography challenges
- Security vulnerability analysis and code review
- Threat modeling and compliance assessment

You have access to utility tools that perform real computations. Use them proactively to
give concrete, actionable analysis rather than just theoretical advice. Explain your
reasoning and what each tool result means.

Never provide instructions for attacking real systems without authorization.
Always focus on educational, CTF, and authorized security testing contexts."""

TOOLS = [
    {
        "name": "decode_text",
        "description": (
            "Decode text from encodings common in CTF challenges: base64, hex, rot13, "
            "url, binary. Use 'auto' to try all of them at once."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The encoded text to decode"},
                "encoding": {
                    "type": "string",
                    "enum": ["base64", "hex", "rot13", "url", "binary", "auto"],
                    "description": "Encoding type, or 'auto' to try all.",
                },
            },
            "required": ["text", "encoding"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "identify_hash",
        "description": (
            "Identify the likely hash algorithm for a hash string based on its length "
            "and character set. Also returns relevant hashcat attack commands."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_string": {
                    "type": "string",
                    "description": "The hash string to identify",
                }
            },
            "required": ["hash_string"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "find_flags",
        "description": (
            "Search text for CTF flag patterns: flag{...}, CTF{...}, picoCTF{...}, "
            "HTB{...}, THM{...}, and generic WORD{...} patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan for flags"}
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "caesar_brute_force",
        "description": "Try all 25 Caesar cipher rotations on a ciphertext and return every result.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Ciphertext to brute-force"}
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "detect_encoding",
        "description": (
            "Analyze a string's character set and structure to suggest likely encodings "
            "(base64, hex, binary, URL, hash type, JWT, substitution cipher, etc.)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to analyze"}
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


# ── Tool implementations ──────────────────────────────────────────────────────

def _decode_text(text: str, encoding: str) -> str:
    def try_base64(t: str) -> str:
        try:
            padded = t.strip() + "=" * (-len(t.strip()) % 4)
            return base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception as e:
            return f"[Error: {e}]"

    def try_hex(t: str) -> str:
        try:
            clean = t.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
            if len(clean) % 2 != 0:
                return "[Error: odd-length hex string]"
            return bytes.fromhex(clean).decode("utf-8", errors="replace")
        except Exception as e:
            return f"[Error: {e}]"

    def try_rot13(t: str) -> str:
        return codecs.decode(t, "rot_13")

    def try_url(t: str) -> str:
        return unquote(t)

    def try_binary(t: str) -> str:
        try:
            clean = t.replace(" ", "")
            if not all(c in "01" for c in clean):
                return "[Error: contains non-binary characters]"
            if len(clean) % 8 != 0:
                return f"[Error: length {len(clean)} not divisible by 8]"
            return "".join(chr(int(clean[i : i + 8], 2)) for i in range(0, len(clean), 8))
        except Exception as e:
            return f"[Error: {e}]"

    decoders = {
        "base64": try_base64,
        "hex": try_hex,
        "rot13": try_rot13,
        "url": try_url,
        "binary": try_binary,
    }

    if encoding == "auto":
        return "\n".join(
            f"{name}: {fn(text)}" for name, fn in decoders.items()
        )
    fn = decoders.get(encoding)
    return fn(text) if fn else f"Unknown encoding: {encoding}"


def _identify_hash(hash_string: str) -> str:
    h = hash_string.strip()
    h_lower = h.lower()
    length = len(h)
    is_hex = all(c in "0123456789abcdef" for c in h_lower)

    candidates: list[str] = []

    if h.startswith(("$2a$", "$2b$", "$2y$")):
        candidates.append("bcrypt")
    elif h.startswith("$1$"):
        candidates.append("MD5-crypt")
    elif h.startswith("$5$"):
        candidates.append("SHA-256-crypt")
    elif h.startswith("$6$"):
        candidates.append("SHA-512-crypt")
    elif is_hex:
        hex_map = {32: ["MD5"], 40: ["SHA-1"], 56: ["SHA-224"],
                   64: ["SHA-256"], 96: ["SHA-384"], 128: ["SHA-512"]}
        candidates.extend(hex_map.get(length, [f"Unknown hex hash (length {length})"]))
    else:
        candidates.append("Unknown / non-standard format")

    hashcat_modes = {"MD5": "0", "SHA-1": "100", "SHA-224": "1300",
                     "SHA-256": "1400", "SHA-384": "10800", "SHA-512": "1700"}

    lines = [f"Hash   : {h}", f"Length : {length}", f"Type(s): {', '.join(candidates)}"]
    if is_hex:
        lines.append("\nSuggested hashcat commands:")
        for algo in candidates:
            if algo in hashcat_modes:
                lines.append(
                    f"  {algo}: hashcat -m {hashcat_modes[algo]} hash.txt wordlist.txt"
                )
        lines.append("  (also try online: crackstation.net, hashes.com)")
    return "\n".join(lines)


def _find_flags(text: str) -> str:
    patterns = [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"pico[Cc][Tt][Ff]\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"THM\{[^}]+\}",
        r"UCTF\{[^}]+\}",
        r"[A-Z]{2,10}\{[A-Za-z0-9_\-+/=!@#$%^&*.,?]{3,}\}",
    ]
    found = list(dict.fromkeys(
        m for pat in patterns
        for m in re.findall(pat, text, re.IGNORECASE)
    ))
    if found:
        return f"Found {len(found)} potential flag(s):\n" + "\n".join(f"  {f}" for f in found)
    return "No obvious flag patterns found. The flag may be encoded, hidden, or use a non-standard wrapper."


def _caesar_brute_force(text: str) -> str:
    lines = []
    for shift in range(1, 26):
        decoded = []
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                decoded.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                decoded.append(c)
        lines.append(f"Shift {shift:2d}: {''.join(decoded)}")
    return "\n".join(lines)


def _detect_encoding(text: str) -> str:
    t = text.strip()
    hints: list[str] = []

    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    b64url_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

    if all(c in b64_chars for c in t) and len(t) % 4 == 0:
        hints.append("Likely standard base64 (valid charset, length divisible by 4)")
    elif all(c in b64url_chars for c in t):
        hints.append("Possibly base64url (URL-safe base64, used in JWTs)")

    hex_chars = set("0123456789abcdefABCDEF")
    if all(c in hex_chars for c in t) and len(t) % 2 == 0:
        hash_map = {32: "MD5", 40: "SHA-1", 56: "SHA-224",
                    64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
        if len(t) in hash_map:
            hints.append(f"Could be a {hash_map[len(t)]} hash ({len(t)} hex chars)")
        else:
            hints.append(f"Likely hex-encoded bytes ({len(t) // 2} bytes)")

    clean_bin = t.replace(" ", "")
    if all(c in "01" for c in clean_bin) and len(clean_bin) % 8 == 0:
        hints.append(f"Likely binary ({len(clean_bin) // 8} bytes)")

    if "%" in t:
        decoded = unquote(t)
        if decoded != t:
            hints.append("Contains URL-encoded characters")

    if t.count(".") == 2:
        parts = t.split(".")
        if all(all(c in b64url_chars for c in p) for p in parts):
            hints.append("Looks like a JWT (three base64url sections separated by dots)")

    if all(c.isalpha() or c in " \n\t.,!?;:'\"-" for c in t):
        hints.append("Only alphabetic text — possible substitution cipher (Caesar, Vigenère, etc.)")

    if not hints:
        hints.append("No strong encoding pattern detected; may be plaintext or a custom format")

    return "\n".join(f"• {h}" for h in hints)


# ── Tool dispatcher ───────────────────────────────────────────────────────────

def _execute_tool(name: str, tool_input: dict) -> str:
    dispatch = {
        "decode_text": lambda: _decode_text(tool_input["text"], tool_input["encoding"]),
        "identify_hash": lambda: _identify_hash(tool_input["hash_string"]),
        "find_flags": lambda: _find_flags(tool_input["text"]),
        "caesar_brute_force": lambda: _caesar_brute_force(tool_input["text"]),
        "detect_encoding": lambda: _detect_encoding(tool_input["text"]),
    }
    fn = dispatch.get(name)
    return fn() if fn else f"Unknown tool: {name}"


# ── Task prompt builder ───────────────────────────────────────────────────────

def _build_user_prompt(task: str, content: str) -> str:
    intros = {
        "ctf_crypto": (
            "Analyze this CTF cryptography challenge. Identify the cipher or encoding, "
            "attempt to decode/crack it using your tools, and explain your approach step by step."
        ),
        "ctf_web": (
            "Analyze this web security challenge. Look for vulnerabilities, interesting "
            "cookies/headers, injection points, IDOR, or hidden flags."
        ),
        "ctf_forensics": (
            "Analyze this forensics challenge. Look for hidden data, encoding, metadata clues, "
            "or embedded flags. Describe what tools to use and why."
        ),
        "ctf_reverse": (
            "Help analyze this reverse engineering challenge. Identify the language/platform, "
            "explain what the code/binary does, and suggest how to extract the flag."
        ),
        "ctf_steganography": (
            "Analyze this steganography challenge. Identify possible hiding techniques "
            "and suggest tools (steghide, zsteg, binwalk, exiftool, etc.). If text is provided, "
            "analyze it for encoding patterns."
        ),
        "vulnerability_scan": (
            "Perform a vulnerability assessment. Identify likely CVEs, insecure patterns, "
            "weak authentication, injection risks, and provide severity + remediation."
        ),
        "code_review": (
            "Review this code for security issues: hardcoded secrets, injection flaws, "
            "insecure crypto, path traversal, XSS, CSRF, and other OWASP Top 10 issues."
        ),
        "password_strength": (
            "Evaluate this password or policy for strength, entropy, and resistance "
            "to brute force and dictionary attacks. Recommend best practices."
        ),
        "threat_assessment": (
            "Perform a threat assessment. Identify threat actors, attack paths, "
            "exposure factors, and mitigation strategies."
        ),
        "compliance_check": (
            "Check this system or policy for security compliance gaps against "
            "NIST, OWASP, ISO 27001, SOC 2, GDPR, or PCI DSS as applicable."
        ),
        "malware_analysis": (
            "Analyze this artifact for malware behavior: persistence, exfiltration, "
            "C2 patterns, privilege escalation, encoded payloads, or ransomware indicators."
        ),
    }
    intro = intros.get(task, "Analyze the following for security implications.")
    return f"{intro}\n\nInput:\n{content}"


# ── Public interface ──────────────────────────────────────────────────────────

def run_agent(task: str, content: str) -> str:
    """Run the agentic loop and return the final text response."""
    messages = [{"role": "user", "content": _build_user_prompt(task, content)}]
    output_parts: list[str] = []

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        for block in response.content:
            if block.type == "text" and block.text:
                output_parts.append(block.text)

        if response.stop_reason != "tool_use":
            break

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        messages.append({"role": "assistant", "content": response.content})

        tool_results = [
            {
                "type": "tool_result",
                "tool_use_id": tb.id,
                "content": _execute_tool(tb.name, tb.input),
            }
            for tb in tool_use_blocks
        ]
        messages.append({"role": "user", "content": tool_results})

    return "\n\n".join(output_parts) if output_parts else "No analysis returned."
