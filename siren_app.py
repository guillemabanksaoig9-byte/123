#!/usr/bin/env python3
"""Aplicativo de sirene remota (Controlador + Receptor).

Melhorias implementadas:
- Arquitetura mais robusta com estado thread-safe e logs estruturados.
- Segurança com validação de token em comparação de tempo constante.
- Endpoints JSON consistentes e tratamento de erros HTTP.
- Interface web com atualização periódica de status.
- Sirene policial mais rápida (cliente e receptor).
"""

from __future__ import annotations

import argparse
import hmac
import html
import json
import logging
import math
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import wave
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

LOCALHOSTS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("siren-app")


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _json_response(ok: bool, status: str, message: str, **extra: object) -> str:
    payload = {"ok": ok, "status": status, "message": message, **extra}
    return json.dumps(payload, ensure_ascii=False)


def _safe_eq(left: Optional[str], right: Optional[str]) -> bool:
    if left is None or right is None:
        return False
    return hmac.compare_digest(left, right)


def _neon_styles() -> str:
    return """
    :root {
      color-scheme: dark;
      --bg: #06060a;
      --card: rgba(13, 18, 32, 0.72);
      --card-border: rgba(255, 255, 255, 0.08);
      --accent: #ff2d55;
      --accent-2: #ff5c5c;
      --accent-3: #ff9f0a;
      --text: #f8fafc;
      --muted: #8b98a7;
      --glow: 0 0 24px rgba(255, 45, 85, 0.45);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #10162c 0%, #06060a 60%, #050508 100%);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: "";
      position: absolute;
      inset: 0;
      background:
        radial-gradient(circle at 15% 20%, rgba(255, 45, 85, 0.22), transparent 40%),
        radial-gradient(circle at 85% 30%, rgba(255, 159, 10, 0.18), transparent 45%),
        radial-gradient(circle at 50% 80%, rgba(93, 86, 255, 0.16), transparent 50%);
      animation: pulse 10s ease-in-out infinite;
      z-index: 0;
    }
    @keyframes pulse { 0%, 100% { opacity: 0.8; } 50% { opacity: 1; } }
    .wrap { width: min(760px, 92vw); position: relative; z-index: 1; }
    .card {
      backdrop-filter: blur(18px);
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 22px;
      padding: 32px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.55), inset 0 0 40px rgba(255, 45, 85, 0.08);
    }
    .title { display: flex; align-items: center; gap: 12px; margin: 0 0 8px; font-size: 30px; }
    .subtitle { color: var(--muted); margin-top: 0; }
    .status-pill {
      display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px;
      border-radius: 999px; background: rgba(255, 45, 85, 0.15); color: var(--accent-2);
      font-weight: 600; box-shadow: var(--glow);
    }
    .status-pill.off { background: rgba(148, 163, 184, 0.18); color: #cbd5f5; box-shadow: none; }
    .grid { display: grid; gap: 14px; margin-top: 24px; }
    .btn {
      width: 100%; border: none; border-radius: 14px; padding: 16px; font-size: 18px;
      font-weight: 700; cursor: pointer; transition: transform 0.15s ease, filter 0.2s;
    }
    .btn:active { transform: translateY(2px); }
    .btn.primary { background: linear-gradient(135deg, var(--accent), #ff7a85); color: #fff; }
    .btn.secondary { background: rgba(15, 23, 42, 0.9); color: #fff; border: 1px solid rgba(255, 255, 255, 0.12); }
    .btn.ghost { background: transparent; color: var(--accent-2); border: 1px solid rgba(255, 92, 92, 0.4); }
    .btn:hover { filter: brightness(1.08); }
    .response { margin-top: 18px; padding: 12px 16px; border-radius: 12px; background: rgba(6, 10, 24, 0.75); }
    .info-row { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; color: var(--muted); }
    """


def _neon_script() -> str:
    return """
    const statusEl = document.querySelector('[data-status]');
    const messageEl = document.querySelector('[data-message]');
    const lastEl = document.querySelector('[data-last]');
    const tokenEl = document.querySelector('[data-token]');
    const statusEndpoint = document.body.dataset.statusEndpoint;

    function setStatus(state, message, last) {
      if (!statusEl) return;
      statusEl.textContent = state;
      statusEl.classList.toggle('off', state.toLowerCase().includes('parad'));
      if (messageEl) messageEl.innerHTML = message || '';
      if (lastEl && typeof last !== 'undefined' && last !== null) lastEl.textContent = last;
    }

    async function postAction(path) {
      const token = tokenEl ? tokenEl.value : '';
      const body = token ? new URLSearchParams({ token }).toString() : '';
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'X-Requested-With': 'fetch' },
        body
      });
      const payload = await response.json();
      setStatus(payload.status || 'Falha', payload.message ? `<strong>${payload.message}</strong>` : '', payload.last_emit_at);
      return payload;
    }

    function playFastPoliceSiren(durationMs = 3000) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = window._audioCtx || (window._audioCtx = new Ctx());
      const oscA = ctx.createOscillator();
      const oscB = ctx.createOscillator();
      const gain = ctx.createGain();
      oscA.type = 'sawtooth';
      oscB.type = 'square';
      gain.gain.value = 0.12;
      oscA.connect(gain).connect(ctx.destination);
      oscB.connect(gain);
      oscA.start();
      oscB.start();

      let high = false;
      const interval = setInterval(() => {
        high = !high;
        const f = high ? 1650 : 760;
        oscA.frequency.setValueAtTime(f, ctx.currentTime);
        oscB.frequency.setValueAtTime(f * 1.015, ctx.currentTime);
      }, 90);

      setTimeout(() => {
        clearInterval(interval);
        oscA.stop();
        oscB.stop();
      }, durationMs);
    }

    async function refreshStatus() {
      if (!statusEndpoint) return;
      try {
        const r = await fetch(statusEndpoint, { headers: { Accept: 'application/json' } });
        if (!r.ok) return;
        const p = await r.json();
        setStatus(p.running ? 'Tocando' : 'Parada', '', p.last_emit_at || '—');
      } catch (_) {}
    }

    document.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          const action = btn.dataset.action;
          const payload = await postAction(action);
          if (payload.ok && action === '/emit') playFastPoliceSiren();
          refreshStatus();
        } catch (_) {
          setStatus('Falha', 'Não foi possível comunicar com o receptor.', null);
        } finally {
          btn.disabled = false;
        }
      });
    });

    refreshStatus();
    setInterval(refreshStatus, 3000);
    """


class SirenPlayer:
    """Player de sirene policial (wail + yelp), inspirado no app de referência."""

    SAMPLE_RATE = 44100
    AMPLITUDE = 30000

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._wail_path, self._yelp_path = self._ensure_wav_files()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._play_loop, daemon=True, name="siren-player")
            self._thread.start()
            LOG.info("Sirene iniciada")

    def stop(self) -> None:
        self._stop_event.set()
        LOG.info("Sinal de parada enviado para a sirene")

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _play_loop(self) -> None:
        while not self._stop_event.is_set():
            self._play(self._wail_path)
            if not self._stop_event.is_set():
                self._play(self._yelp_path)

    def _generate_sweep(self, duration: float, freq_lo: float, freq_hi: float, cycle: float) -> bytes:
        n = int(self.SAMPLE_RATE * duration)
        phase = 0.0
        samples: list[int] = []
        for i in range(n):
            t = i / self.SAMPLE_RATE
            sweep = (math.sin(2 * math.pi * t / cycle - math.pi / 2) + 1) / 2
            freq = freq_lo + (freq_hi - freq_lo) * sweep
            phase += 2 * math.pi * freq / self.SAMPLE_RATE
            sample = int(self.AMPLITUDE * math.sin(phase))
            samples.append(max(-32767, min(32767, sample)))
        return struct.pack(f"<{len(samples)}h", *samples)

    def _write_wav(self, pcm: bytes, path: str) -> None:
        with wave.open(path, "w") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(self.SAMPLE_RATE)
            wf.writeframes(pcm)

    def _ensure_wav_files(self) -> tuple[str, str]:
        tmp = tempfile.gettempdir()
        wail = os.path.join(tmp, "police_wail.wav")
        yelp = os.path.join(tmp, "police_yelp.wav")
        if not os.path.exists(wail):
            self._write_wav(self._generate_sweep(4.0, 600, 1600, 4.0), wail)
        if not os.path.exists(yelp):
            self._write_wav(self._generate_sweep(2.0, 800, 1600, 0.3), yelp)
        return wail, yelp

    def _play(self, path: str) -> None:
        if self._stop_event.is_set():
            return
        if os.name == "nt":
            self._play_windows(path)
            return

        self._play_unix(path)

    def _play_windows(self, path: str) -> None:
        try:
            import winsound

            winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_NODEFAULT)
            return
        except Exception:
            pass

        try:
            import winsound

            for freq in range(600, 1600, 50):
                if self._stop_event.is_set():
                    return
                winsound.Beep(freq, 30)
            for freq in range(1600, 600, -50):
                if self._stop_event.is_set():
                    return
                winsound.Beep(freq, 30)
        except Exception:
            return

    def _play_unix(self, path: str) -> None:
        for cmd in ("paplay", "aplay", "play"):
            if not shutil.which(cmd):
                continue
            player_cmd = [cmd, path] if cmd in {"paplay", "aplay"} else [cmd, path]
            try:
                proc = subprocess.Popen(player_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                while proc.poll() is None:
                    if self._stop_event.is_set():
                        proc.terminate()
                        proc.wait(timeout=2)
                        return
                    time.sleep(0.1)
                return
            except OSError:
                continue

        # fallback universal (som do terminal)
        for _ in range(8):
            if self._stop_event.is_set():
                return
            print("\a", end="", flush=True)
            time.sleep(0.25)


@dataclass
class ReceiverState:
    token: Optional[str]
    player: SirenPlayer = field(default_factory=SirenPlayer)
    last_emit_at: Optional[str] = None

    def emit(self) -> None:
        self.player.start()
        self.last_emit_at = _now()

    def stop(self) -> None:
        self.player.stop()


class BaseHandler(BaseHTTPRequestHandler):
    server_version = "SirenApp/2.0"

    def _write(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _wants_json(self) -> bool:
        accept = self.headers.get("Accept", "")
        return "application/json" in accept or self.headers.get("X-Requested-With") == "fetch"

    def log_message(self, format: str, *args: object) -> None:
        LOG.info("%s - %s", self.address_string(), format % args)


class ReceiverHandler(BaseHandler):
    state: ReceiverState

    def _is_local(self) -> bool:
        return self.client_address[0] in LOCALHOSTS

    def _read_post(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode("utf-8") if length else ""
        return dict(urllib.parse.parse_qsl(data))

    def _token_from_request(self) -> Optional[str]:
        if token := self.headers.get("X-Token"):
            return token
        parsed = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        if token := query.get("token"):
            return token
        return self._read_post().get("token")

    def _authorize(self) -> bool:
        if self.state.token is None:
            return True
        return _safe_eq(self._token_from_request(), self.state.token)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/status":
            body = json.dumps({"running": self.state.player.is_running(), "last_emit_at": self.state.last_emit_at})
            self._write(HTTPStatus.OK, body, "application/json")
            return

        if parsed.path == "/" and self._is_local():
            status = "Tocando" if self.state.player.is_running() else "Parada"
            last = self.state.last_emit_at or "—"
            body = f"""
            <html><head><meta charset='utf-8'><title>Receptor</title><style>{_neon_styles()}</style></head>
            <body data-status-endpoint='/status'><div class='wrap'><div class='card'>
              <h1 class='title'>🚨 Receptor da Sirene</h1>
              <p class='subtitle'>Console local do receptor.</p>
              <div class='info-row'><span>Status: <span class='status-pill {'' if status == 'Tocando' else 'off'}' data-status>{status}</span></span>
              <span>Último acionamento: <strong data-last>{html.escape(last)}</strong></span></div>
              <div class='grid'><button class='btn secondary' data-action='/stop'>Parar Sirene</button></div>
              <div class='response' data-message>No receptor, apenas a ação de parada fica disponível.</div>
            </div></div><script>{_neon_script()}</script></body></html>
            """
            self._write(HTTPStatus.OK, body)
            return

        if parsed.path == "/simple":
            token_hint = html.escape(self._token_from_request() or "")
            body = f"""
            <html><head><meta charset='utf-8'><title>Controle</title><style>{_neon_styles()}</style></head>
            <body data-status-endpoint='/status'><div class='wrap'><div class='card'>
              <h1 class='title'>🚨 Emitir Sirene</h1>
              <p class='subtitle'>A página do receptor permite somente parar.</p>
              <div class='info-row'><span class='status-pill off' data-status>Parada</span></div>
              <input type='hidden' data-token value='{token_hint}' />
              <div class='grid'><button class='btn secondary' data-action='/stop'>Parar Sirene</button></div>
              <div class='response' data-message>Para ligar a sirene, use o painel do controlador.</div>
            </div></div><script>{_neon_script()}</script></body></html>
            """
            self._write(HTTPStatus.OK, body)
            return

        self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/emit":
            if not self._authorize():
                body = _json_response(False, "Não autorizado", "Token inválido ou ausente.")
                self._write(HTTPStatus.UNAUTHORIZED, body, "application/json")
                return
            self.state.emit()
            body = _json_response(True, "Ligada", "A sirene foi ligada com sucesso.", last_emit_at=self.state.last_emit_at)
            self._write(HTTPStatus.OK, body, "application/json")
            return

        if parsed.path == "/stop":
            if not self._is_local() and not self._authorize():
                body = _json_response(False, "Acesso negado", "Somente acesso local ou com token válido.")
                self._write(HTTPStatus.FORBIDDEN, body, "application/json")
                return
            self.state.stop()
            body = _json_response(True, "Parada", "A sirene foi parada.", last_emit_at=self.state.last_emit_at)
            self._write(HTTPStatus.OK, body, "application/json")
            return

        self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")


class ControllerHandler(BaseHandler):
    receiver_url: str
    token: Optional[str]

    def _build_receiver_request(self, path: str, *, method: str, data: Optional[bytes] = None) -> urllib.request.Request:
        req = urllib.request.Request(urllib.parse.urljoin(self.receiver_url, path), method=method, data=data)
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-With", "fetch")
        req.add_header("ngrok-skip-browser-warning", "true")
        if self.token:
            req.add_header("X-Token", self.token)
        return req

    def _send_action(self, path: str) -> tuple[bool, str]:
        req = self._build_receiver_request(path, method="POST", data=b"ts=1")
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return bool(payload.get("ok")), str(payload.get("message", ""))
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as exc:
            return False, f"Erro ao contactar receptor: {exc}"

    def _fetch_status(self) -> tuple[bool, dict[str, object]]:
        req = self._build_receiver_request("/status", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return True, payload
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as exc:
            return False, {"running": False, "last_emit_at": None, "error": f"Erro ao consultar receptor: {exc}"}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/status":
            ok, payload = self._fetch_status()
            self._write(HTTPStatus.OK if ok else HTTPStatus.BAD_GATEWAY, json.dumps(payload, ensure_ascii=False), "application/json")
            return

        if self.path != "/":
            self._write(HTTPStatus.NOT_FOUND, "Not found")
            return
        body = f"""
        <html><head><meta charset='utf-8'><title>Controlador</title><style>{_neon_styles()}</style></head>
        <body data-status-endpoint='/status'>
          <div class='wrap'><div class='card'>
            <h1 class='title'>🚨 Controlador Central</h1>
            <p class='subtitle'>Controle remoto robusto do receptor.</p>
            <div class='info-row'><span>Status: <span class='status-pill off' data-status>Parada</span></span>
            <span>Último acionamento: <strong data-last>—</strong></span></div>
            <div class='grid'><button class='btn primary' data-action='/emit'>Ligar Sirene</button>
            <button class='btn secondary' data-action='/stop'>Parar Sirene</button></div>
            <div class='response' data-message>Pronto para enviar comandos ao receptor.</div>
          </div></div><script>{_neon_script()}</script>
        </body></html>
        """
        self._write(HTTPStatus.OK, body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/emit", "/stop"}:
            self._write(HTTPStatus.NOT_FOUND, "Not found")
            return
        ok, message = self._send_action(self.path)
        status = "Ligada" if self.path == "/emit" and ok else "Parada" if ok else "Falha"
        body = _json_response(ok, status, message)
        self._write(HTTPStatus.OK if ok else HTTPStatus.BAD_GATEWAY, body, "application/json")


class ServerRuntime:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server

    def serve_forever(self) -> None:
        def _shutdown(*_: object) -> None:
            LOG.info("Encerrando servidor...")
            self.server.shutdown()

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
        self.server.serve_forever()


class ControllerServer:
    def __init__(self, bind: str, port: int, receiver_url: str, token: Optional[str]) -> None:
        self.bind = bind
        self.port = port
        self.receiver_url = receiver_url.rstrip("/")
        self.token = token

    def serve(self) -> None:
        handler = type("ConfiguredControllerHandler", (ControllerHandler,), {"receiver_url": self.receiver_url, "token": self.token})
        server = ThreadingHTTPServer((self.bind, self.port), handler)
        LOG.info("Controlador ativo em http://%s:%d", self.bind, self.port)
        ServerRuntime(server).serve_forever()


class ReceiverServer:
    def __init__(self, bind: str, port: int, token: Optional[str], ngrok: bool) -> None:
        self.bind = bind
        self.port = port
        self.token = token
        self.ngrok = ngrok
        self._ngrok_process: Optional[subprocess.Popen[bytes]] = None

    def _start_ngrok(self) -> Optional[str]:
        try:
            self._ngrok_process = subprocess.Popen(["ngrok", "http", str(self.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            LOG.warning("Ngrok não encontrado. Use --no-ngrok ou instale o binário.")
            return None

        url = "http://127.0.0.1:4040/api/tunnels"
        for _ in range(16):
            try:
                with urllib.request.urlopen(url, timeout=1) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                tunnels = data.get("tunnels", [])
                if tunnels:
                    return tunnels[0].get("public_url")
            except (urllib.error.URLError, socket.timeout, json.JSONDecodeError):
                time.sleep(0.4)
        LOG.warning("Ngrok iniciou, mas o link público não foi obtido automaticamente.")
        return None

    def serve(self) -> None:
        state = ReceiverState(self.token)
        handler = type("ConfiguredReceiverHandler", (ReceiverHandler,), {"state": state})
        server = ThreadingHTTPServer((self.bind, self.port), handler)
        LOG.info("Receptor ativo em http://%s:%d", self.bind, self.port)
        LOG.info("Parada local em: http://localhost:%d", self.port)
        if self.ngrok:
            public_url = self._start_ngrok()
            if public_url:
                LOG.info("Ngrok iniciado: %s", public_url)
        ServerRuntime(server).serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aplicativo de sirene remota")
    sub = parser.add_subparsers(dest="mode", required=True)

    controller = sub.add_parser("controller", help="Inicia o Controlador Central")
    controller.add_argument("--bind", default="0.0.0.0")
    controller.add_argument("--port", type=int, default=5000)
    controller.add_argument("--receiver-url", required=True, help="URL base do receptor (ex: http://IP:5001)")
    controller.add_argument("--token", help="Token compartilhado com o receptor")

    receiver = sub.add_parser("receiver", help="Inicia o Receptor")
    receiver.add_argument("--bind", default="0.0.0.0")
    receiver.add_argument("--port", type=int, default=5001)
    receiver.add_argument("--token", help="Token compartilhado para autorizar emissão")
    receiver.add_argument("--no-ngrok", dest="ngrok", action="store_false", default=True)

    if len(sys.argv) == 1:
        return parser.parse_args(["receiver"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.mode == "controller":
        ControllerServer(args.bind, args.port, args.receiver_url, args.token).serve()
    elif args.mode == "receiver":
        ReceiverServer(args.bind, args.port, args.token, args.ngrok).serve()


if __name__ == "__main__":
    main()
