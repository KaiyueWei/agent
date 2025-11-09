# CyberSci Agent (Kali)

This repository contains a small interactive agent (`agent.py`) that uses the OpenAI Responses API and a small set of local tools to help with CTF-style cybersecurity challenges. This README covers quick setup for Kali Linux and safety recommendations.

## Quick setup (Kali)

1. Create a Python virtual environment and install Python deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

2. Install system packages (tshark, binwalk, yara, etc.):

```bash
sudo apt update
sudo apt install -y tshark wireshark binwalk yara radare2 binutils git
# Optional but useful:
sudo apt install -y nmap tcpdump
```

3. Allow non-root tshark captures (optional):

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$USER"
newgrp wireshark
```

4. Create a `.env` file with your OpenAI API key (do NOT commit this file):

```
OPENAI_API_KEY=sk-xxx
```

## How `agent.py` works

- Start the REPL: `python agent.py`.
- The agent sends your messages to the Responses API and exposes a small set of tools (e.g., `ping`, `analyze_pcap`).
- When the model requests a tool, the agent prompts you for confirmation before executing it.
- All tool executions are logged to `agent.log` in the workspace.

## Safety

- By default, file-based tools (like `analyze_pcap`) only accept paths inside the repository workspace to avoid accidental access to other files.
- Network actions and file executions require interactive confirmation.
- For risky dynamic analysis, prefer running the agent inside a disposable VM or container.

## Customization

- Edit `tools` in `agent.py` to add/remove tool schemas exposed to the model.
- Adjust subprocess timeouts, output truncation, and the confirmation policy in `agent.py` as needed.

## Troubleshooting

- If `tshark` is not found, install Wireshark/tshark or use `pyshark`.
- If the Responses API shape differs, you may need to adapt `handle_tools` and `tool_call` to match the client response objects.

---

If you want, I can also:
- Add a small REPL command to manage a network whitelist.
- Add a Docker wrapper for running analysis tools in an isolated container.
- Add more tool schemas (disassemble, strings, http_fetch) with safety checks.
