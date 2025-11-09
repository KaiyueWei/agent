from openai import OpenAI
from dotenv import load_dotenv
import os
from typing import NoReturn
import subprocess
import json
from pathlib import Path
import time
import uuid

# Load environment variables from .env
load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OPENAI_API_KEY in environment variables or .env file")

client = OpenAI(api_key=api_key)
context: list[dict[str, str]] = []

# Workspace dir and simple audit log
context_dir = Path(__file__).resolve().parent
LOGFILE = context_dir / "agent.log"

tools = [{
   "type": "function", "name": "ping",
   "description": "ping some host on the internet",
   "parameters": {
       "type": "object", "properties": {
           "host": {
             "type": "string", "description": "hostname or IP",
            },
       },
       "required": ["host"],
    },},
    {
   "type": "function", "name": "analyze_pcap",
   "description": "Analyze a pcap file using tshark. Path must be inside the agent workspace.",
   "parameters": {
       "type": "object", "properties": {
           "path": {"type": "string", "description": "relative or absolute path to pcap file"},
           "filter": {"type": "string", "description": "optional display filter for tshark"}
       },
       "required": ["path"],
    },},]

def ping(host=""):
    try:
        result = subprocess.run(
            ["ping", "-c", "5", host],
            text=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            timeout=10)
        return result.stdout
    except Exception as e:
        return f"error: {e}"
    

def _log(msg: str):
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def analyze_pcap(path: str, filter: str | None = None):
    """Analyze a pcap file using tshark. Restricts path to the workspace directory.
    Returns stdout or an error string.
    """
    try:
        # expand user (~) and resolve relative to workspace
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = (context_dir / p).resolve()
        else:
            p = p.resolve()

        # Ensure path is inside workspace (use relative_to for a robust check)
        try:
            p.relative_to(context_dir)
        except Exception:
            _log(f"analyze_pcap: denied path outside workspace: {p}")
            return f"error: pcap path {p} is outside the workspace ({context_dir})"

        if not p.exists() or not p.is_file():
            _log(f"analyze_pcap: file not found: {p}")
            return f"error: file not found: {p}"

        cmd = ["tshark", "-r", str(p), "-q"]
        if filter:
            cmd += ["-Y", filter]

        result = subprocess.run(cmd, text=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, timeout=15)
        _log(f"analyze_pcap: path={p} filter={filter} exit={result.returncode}")
        out = result.stdout
        if len(out) > 20000:
            out = out[:20000] + "\n... (truncated)"
        return out
    except subprocess.TimeoutExpired:
        return "error: analysis timed out"
    except FileNotFoundError:
        return "error: tshark not found on PATH. Install Wireshark/tshark or use pyshark."
    except Exception as e:
        return f"error: {e}"
    
def call(tools=None, model="gpt-5"):
    # allow callers to pass per-call tools; fall back to global `tools`
    if tools is None:
        tools = globals().get("tools", [])
    # Filter out any internal 'reasoning' items before sending to the API.
    # Some Responses API input validations disallow standalone 'reasoning' items.
    safe_input = []
    for it in context:
        # support both object-like items returned by the client and plain dicts
        t = None
        try:
            t = getattr(it, "type", None)
        except Exception:
            t = None
        if t == "reasoning":
            # skip internal reasoning fragments
            continue
        if isinstance(it, dict) and it.get("type") == "reasoning":
            continue
        safe_input.append(it)

    return client.responses.create(model=model, tools=tools, input=safe_input)

def _extract_call_id(item):
    # defensive extraction for different client shapes
    call_id = getattr(item, "call_id", None) or getattr(item, "id", None)
    try:
        # dict-like fallback
        if not call_id and hasattr(item, "get"):
            call_id = item.get("call_id") or item.get("id")
    except Exception:
        pass
    if not call_id:
        call_id = str(uuid.uuid4())
    return call_id


def tool_call(item):    # handles one tool with confirmation and validation
    try:
        args = json.loads(getattr(item, "arguments", "{}"))
    except Exception as e:
        cid = _extract_call_id(item)
        return [item, {"type": "function_call_output", "call_id": cid, "output": f"error: invalid arguments JSON: {e}"}]

    name = getattr(item, "name", None) or getattr(item, "function", None) or (item.get("name") if hasattr(item, "get") else "<unknown>")
    cid = _extract_call_id(item)

    # Prompt user for confirmation for sensitive actions (file/network)
    print(f"Model requested tool call: {name} with args: {args}")
    resp = input("Allow this tool call? [y/N]: ").strip().lower()
    if resp not in {"y", "yes"}:
        _log(f"tool_call: denied name={name} args={args} call_id={cid}")
        return [item, {"type": "function_call_output", "call_id": cid, "output": "(denied by user)"}]

    try:
        if name == "ping":
            result = ping(**args)
        elif name == "analyze_pcap":
            result = analyze_pcap(**args)
        else:
            result = f"error: unknown tool {name}"
    except Exception as e:
        result = f"error: {e}"

    _log(f"tool_call: executed name={name} args={args} call_id={cid}")
    return [ item, {
        "type": "function_call_output",
        "call_id": cid,
        "output": result
    }]

def handle_tools(tools, response):
    outs = getattr(response, "output", None)
    if not outs:
        return False
    first = outs[0] if len(outs) > 0 else None
    if first and getattr(first, "type", None) == "reasoning":
        context.append(first)
    osz = len(context)
    for item in outs:
        if getattr(item, "type", None) == "function_call":
            context.extend(tool_call(item))
    return len(context) != osz

def process(line):
    context.append({"role": "user", "content": line})
    response = call()
    # resolve tool calls with a safety cap
    for _ in range(6):
        if not handle_tools(tools, response):
            break
        response = call()
    context.append({"role": "assistant", "content": response.output_text})        
    return response.output_text

def main() -> NoReturn:
    """Interactive REPL for the agent."""
    print("🤖 CyberSci Agent ready! Type 'exit' or Ctrl+C to quit.\n")
    while True:
        try:
            line = input("> ").strip()
            if line.lower() in {"exit", "quit"}:
                print("Goodbye 👋")
                break
            result = process(line)
            print(f">>> {result}\n")
        except KeyboardInterrupt:
            print("\nGoodbye 👋")
            break
        except Exception as e:
            print(f"[Error] {e}")

if __name__ == "__main__":
    main()

