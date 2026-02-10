#!/usr/bin/env python3
"""Aplicativo de sirene remota (arquivo único, sem dependências externas).

Melhorias principais:
- Estrutura reescrita e modular dentro de um único arquivo.
- Modo explícito: receiver | controller | both.
- UI separada e inequívoca para receptor e controlador.
- Cliente HTTP robusto com diagnóstico detalhado.
- Token opcional com comparação em tempo constante.
- Estado do receptor thread-safe.
"""

from __future__ import annotations

import argparse
import hmac
import html
import itertools
import json
import logging
import math
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import wave
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

LOCALHOSTS = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}
LOG = logging.getLogger("siren-app")
RID_COUNTER = itertools.count(1)


# =========================
# Utilitários
# =========================


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_eq(left: Optional[str], right: Optional[str]) -> bool:
    if left is None or right is None:
        return False
    return hmac.compare_digest(left, right)


def mask_secret(secret: Optional[str]) -> str:
    if not secret:
        return "(none)"
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"


def detect_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def find_available_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", preferred))
            return preferred
        except OSError:
            sock.bind(("", 0))
            return int(sock.getsockname()[1])


def request_id() -> str:
    return f"r{int(time.time() * 1000)}-{next(RID_COUNTER)}"


def json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


# =========================
# Interface
# =========================


def neon_styles() -> str:
    return """
    :root {
      color-scheme: dark;
      --card: rgba(13, 18, 32, 0.72);
      --card-border: rgba(255, 255, 255, 0.08);
      --accent: #ff2d55;
      --text: #f8fafc;
      --muted: #8b98a7;
      --receiver: #0ea5e9;
      --controller: #a855f7;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #10162c 0%, #06060a 60%, #050508 100%);
      color: var(--text); min-height: 100vh; display: flex;
      align-items: center; justify-content: center;
    }
    .wrap { width: min(920px, 94vw); }
    .card {
      backdrop-filter: blur(18px); background: var(--card);
      border: 1px solid var(--card-border); border-radius: 20px;
      padding: 28px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    }
    .title { margin: 0 0 8px; font-size: 30px; }
    .subtitle { color: var(--muted); margin-top: 0; }
    .banner { border-radius: 12px; padding: 10px 14px; margin-bottom: 14px; font-weight: 700; }
    .banner.receiver { background: rgba(14,165,233,0.2); border: 1px solid rgba(14,165,233,0.45); }
    .banner.controller { background: rgba(168,85,247,0.2); border: 1px solid rgba(168,85,247,0.45); }
    .status-pill {
      display: inline-flex; padding: 6px 12px; border-radius: 999px;
      background: rgba(255,45,85,0.2); color: #fecdd3; font-weight: 700;
    }
    .status-pill.off { background: rgba(148, 163, 184, 0.2); color: #cbd5f5; }
    .grid { display: grid; gap: 12px; margin-top: 14px; }
    .btn {
      width: 100%; border: none; border-radius: 12px; padding: 14px;
      font-size: 18px; font-weight: 700; cursor: pointer;
    }
    .btn.primary { background: linear-gradient(135deg, #ff2d55, #ff7a85); color: #fff; }
    .btn.secondary { background: rgba(15,23,42,0.95); color: #fff; border: 1px solid rgba(255,255,255,0.12); }
    .btn.warning { background: linear-gradient(135deg, #f59e0b, #fbbf24); color: #111827; }
    .response { margin-top: 16px; padding: 12px 14px; border-radius: 10px; background: rgba(6,10,24,0.8); }
    .info-row { display: flex; flex-wrap: wrap; gap: 10px 14px; color: var(--muted); }
    .links a { color: #fda4af; text-decoration: none; }
    code { background: rgba(30,41,59,0.75); border-radius: 7px; padding: 1px 6px; }
    """


def neon_script() -> str:
    return """
    const statusEl = document.querySelector('[data-status]');
    const messageEl = document.querySelector('[data-message]');
    const lastEl = document.querySelector('[data-last]');
    const endpointStatus = document.body.dataset.statusEndpoint || '';

    function setStatus(state, message, last) {
      if (statusEl && state) {
        statusEl.textContent = state;
        statusEl.classList.toggle('off', state.toLowerCase().includes('parad') || state.toLowerCase().includes('off'));
      }
      if (messageEl && typeof message === 'string') messageEl.innerHTML = message;
      if (lastEl && (last || last === '')) lastEl.textContent = last || '—';
    }

    function playFastPoliceSiren(durationMs = 2800) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = window._audioCtx || (window._audioCtx = new Ctx());
      const oscA = ctx.createOscillator();
      const oscB = ctx.createOscillator();
      const gain = ctx.createGain();
      oscA.type = 'sawtooth';
      oscB.type = 'square';
      gain.gain.value = 0.11;
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

    async function postAction(path) {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'X-Requested-With': 'fetch' }
      });
      const payload = await response.json();
      const statusText = payload.status || (payload.ok ? 'OK' : 'Falha');
      const extra = payload.receiver_status ? `<br><small>receiver_status=${payload.receiver_status}</small>` : '';
      setStatus(statusText, `<strong>${payload.message || ''}</strong>${extra}`, payload.last_emit_at || '—');
      return payload;
    }

    async function refreshStatus() {
      if (!endpointStatus) return;
      try {
        const r = await fetch(endpointStatus, { headers: { Accept: 'application/json' } });
        const p = await r.json();
        if (p.running === true) setStatus('Tocando', messageEl ? messageEl.innerHTML : '', p.last_emit_at || '—');
        if (p.running === false) setStatus('Parada', messageEl ? messageEl.innerHTML : '', p.last_emit_at || '—');
      } catch (_) {}
    }

    document.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const action = btn.dataset.action;
        try {
          const payload = await postAction(action);
          if (payload.ok && action.includes('/emit')) playFastPoliceSiren();
          await refreshStatus();
        } catch (_) {
          setStatus('Falha', '<strong>Erro de rede ao executar ação.</strong>', null);
        } finally {
          btn.disabled = false;
        }
      });
    });

    refreshStatus();
    setInterval(refreshStatus, 3000);
    """


def layout_page(*, title: str, subtitle: str, banner_class: str, banner_text: str, body_html: str, status_endpoint: str) -> str:
    return f"""
    <html>
      <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>{html.escape(title)}</title>
        <style>{neon_styles()}</style>
      </head>
      <body data-status-endpoint='{html.escape(status_endpoint)}'>
        <div class='wrap'>
          <div class='card'>
            <div class='banner {html.escape(banner_class)}'>{html.escape(banner_text)}</div>
            <h1 class='title'>🚨 {html.escape(title)}</h1>
            <p class='subtitle'>{html.escape(subtitle)}</p>
            {body_html}
          </div>
        </div>
        <script>{neon_script()}</script>
      </body>
    </html>
    """


# =========================
# Sirene
# =========================

class SirenPlayer:
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
        else:
            self._play_unix(path)

    def _play_windows(self, path: str) -> None:
        import winsound

        try:
            winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_NODEFAULT)
            return
        except RuntimeError:
            pass

        for freq in range(600, 1600, 50):
            if self._stop_event.is_set():
                return
            winsound.Beep(freq, 30)

    def _play_unix(self, path: str) -> None:
        for cmd in ("paplay", "aplay", "play"):
            if not shutil.which(cmd):
                continue
            try:
                proc = subprocess.Popen([cmd, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                while proc.poll() is None:
                    if self._stop_event.is_set():
                        proc.terminate()
                        proc.wait(timeout=2)
                        return
                    time.sleep(0.1)
                return
            except OSError:
                continue

        for _ in range(8):
            if self._stop_event.is_set():
                return
            print("\a", end="", flush=True)
            time.sleep(0.25)


# =========================
# Estado
# =========================

@dataclass
class ReceiverState:
    token: Optional[str]
    player: SirenPlayer
    lock: threading.Lock
    last_emit_at: Optional[str] = None

    @classmethod
    def create(cls, token: Optional[str]) -> "ReceiverState":
        return cls(token=token, player=SirenPlayer(), lock=threading.Lock())

    def emit(self) -> str:
        with self.lock:
            self.player.start()
            self.last_emit_at = now_iso()
            return self.last_emit_at

    def stop(self) -> None:
        with self.lock:
            self.player.stop()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"running": self.player.is_running(), "last_emit_at": self.last_emit_at}


# =========================
# HTTP shared
# =========================

class BaseHandler(BaseHTTPRequestHandler):
    server_version = "SirenApp/3.0"

    def _parsed(self) -> urllib.parse.ParseResult:
        return urllib.parse.urlparse(self.path)

    def _is_local(self) -> bool:
        return self.client_address[0] in LOCALHOSTS

    def _new_request_id(self) -> str:
        return self.headers.get("X-Request-Id") or request_id()

    def _wants_json(self) -> bool:
        accept = self.headers.get("Accept", "")
        return "application/json" in accept or self.headers.get("X-Requested-With") == "fetch"

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode("utf-8") if length else ""
        return dict(urllib.parse.parse_qsl(data))

    def _token_from_request(self) -> Optional[str]:
        if token := self.headers.get("X-Token"):
            return token
        parsed = self._parsed()
        query = dict(urllib.parse.parse_qsl(parsed.query))
        if token := query.get("token"):
            return token
        form = self._read_form()
        return form.get("token")

    def _write(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._write(status, json_text(payload), "application/json; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        LOG.info("%s - %s", self.address_string(), format % args)


# =========================
# Receptor server
# =========================

@dataclass
class ReceiverServerConfig:
    bind: str
    port: int
    token: Optional[str]
    controller_url: Optional[str]


class ReceiverHandler(BaseHandler):
    cfg: ReceiverServerConfig
    state: ReceiverState

    def _authorize(self) -> bool:
        if self.cfg.token is None:
            return True
        return safe_eq(self._token_from_request(), self.cfg.token)

    def do_GET(self) -> None:  # noqa: N802
        rid = self._new_request_id()
        parsed = self._parsed()

        if parsed.path == "/status":
            snap = self.state.snapshot()
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "status": "OK",
                    "message": "Estado do receptor.",
                    "request_id": rid,
                    "running": snap["running"],
                    "last_emit_at": snap["last_emit_at"],
                    "receiver_port": self.cfg.port,
                },
            )
            return

        if parsed.path != "/":
            self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
            return

        snap = self.state.snapshot()
        status_text = "Tocando" if snap["running"] else "Parada"
        last_emit_at = snap["last_emit_at"] or "—"

        controller_block = (
            f"<div class='links'><strong>Painel controlador:</strong> "
            f"<a href='{html.escape(self.cfg.controller_url or '')}' target='_blank'>{html.escape(self.cfg.controller_url or 'não configurado')}</a></div>"
            if self.cfg.controller_url
            else "<div class='links'><strong>Painel controlador:</strong> não configurado.</div>"
        )

        body = f"""
        <div class='info-row'>
          <span>Papel: <code>RECEPTOR</code></span>
          <span>Host/porta: <code>{html.escape(self.cfg.bind)}:{self.cfg.port}</code></span>
          <span>Status: <span class='status-pill {'off' if status_text == 'Parada' else ''}' data-status>{status_text}</span></span>
          <span>Último acionamento: <strong data-last>{html.escape(last_emit_at)}</strong></span>
        </div>
        <div class='grid'>
          <button class='btn warning' data-action='/stop'>Parar Sirene no Receptor</button>
        </div>
        <div class='response' data-message>
          Este painel é do receptor. A ação de <strong>ligar</strong> deve ser feita no controlador.
        </div>
        {controller_block}
        <div class='response'>
          Endpoints: <code>GET /status</code> | <code>POST /emit</code> | <code>POST /stop</code>
        </div>
        """
        page = layout_page(
            title="Receptor da Sirene",
            subtitle="Nó responsável por tocar o áudio.",
            banner_class="receiver",
            banner_text="Você está no RECEPTOR (som local)",
            body_html=body,
            status_endpoint="/status",
        )
        self._write(HTTPStatus.OK, page)

    def do_POST(self) -> None:  # noqa: N802
        rid = self._new_request_id()
        parsed = self._parsed()

        if parsed.path == "/emit":
            if not self._authorize():
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {
                        "ok": False,
                        "status": "Não autorizado",
                        "message": "Token inválido ou ausente.",
                        "request_id": rid,
                    },
                )
                return
            last = self.state.emit()
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "status": "Ligada",
                    "message": "A sirene foi ligada com sucesso.",
                    "request_id": rid,
                    "last_emit_at": last,
                },
            )
            return

        if parsed.path == "/stop":
            if not self._is_local() and not self._authorize():
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "ok": False,
                        "status": "Acesso negado",
                        "message": "Somente acesso local ou token válido.",
                        "request_id": rid,
                    },
                )
                return
            self.state.stop()
            snap = self.state.snapshot()
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "status": "Parada",
                    "message": "A sirene foi parada.",
                    "request_id": rid,
                    "last_emit_at": snap["last_emit_at"],
                },
            )
            return

        self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")


# =========================
# Cliente do receptor para controlador
# =========================

@dataclass
class ReceiverClientResult:
    ok: bool
    message: str
    status: str
    receiver_status: Optional[int] = None
    details: Optional[dict[str, Any]] = None


class ReceiverClient:
    def __init__(self, receiver_url: str, token: Optional[str], timeout: float = 4.0) -> None:
        self.receiver_url = receiver_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, path: str, method: str) -> ReceiverClientResult:
        rid = request_id()
        url = urllib.parse.urljoin(self.receiver_url + "/", path.lstrip("/"))
        req = urllib.request.Request(url, method=method, data=b"ts=1" if method == "POST" else None)
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-With", "fetch")
        req.add_header("X-Request-Id", rid)
        req.add_header("ngrok-skip-browser-warning", "true")
        if self.token:
            req.add_header("X-Token", self.token)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return ReceiverClientResult(
                    ok=bool(payload.get("ok", True)),
                    message=str(payload.get("message", "OK")),
                    status=str(payload.get("status", "OK")),
                    receiver_status=resp.status,
                    details=payload,
                )
        except urllib.error.HTTPError as exc:
            body = ""
            parsed: dict[str, Any] = {}
            try:
                body = exc.read().decode("utf-8")
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = {"raw": body}

            msg = parsed.get("message") if isinstance(parsed, dict) else None
            if not msg:
                if exc.code == 401:
                    msg = "Não autorizado no receptor (token inválido ou ausente)."
                elif exc.code == 403:
                    msg = "Acesso negado no receptor (ação proibida)."
                elif exc.code == 404:
                    msg = "Endpoint não encontrado no receptor."
                else:
                    msg = f"Erro HTTP no receptor: {exc.code}."
            return ReceiverClientResult(False, str(msg), "Falha", receiver_status=exc.code, details=parsed)
        except urllib.error.URLError as exc:
            return ReceiverClientResult(False, f"Receptor indisponível: {exc.reason}", "Falha", details={"error": str(exc)})
        except socket.timeout:
            return ReceiverClientResult(False, "Timeout ao contactar receptor.", "Falha")
        except json.JSONDecodeError:
            return ReceiverClientResult(False, "Resposta inválida do receptor.", "Falha")

    def status(self) -> ReceiverClientResult:
        return self._request("/status", "GET")

    def emit(self) -> ReceiverClientResult:
        return self._request("/emit", "POST")

    def stop(self) -> ReceiverClientResult:
        return self._request("/stop", "POST")


# =========================
# Controlador server
# =========================

@dataclass
class ControllerServerConfig:
    bind: str
    port: int
    receiver_url: str
    token: Optional[str]


class ControllerHandler(BaseHandler):
    cfg: ControllerServerConfig

    def _client(self) -> ReceiverClient:
        return ReceiverClient(self.cfg.receiver_url, self.cfg.token)

    def do_GET(self) -> None:  # noqa: N802
        rid = self._new_request_id()
        parsed = self._parsed()

        if parsed.path == "/status":
            result = self._client().status()
            if not result.ok:
                self._json(
                    HTTPStatus.BAD_GATEWAY,
                    {
                        "ok": False,
                        "status": "Falha",
                        "message": result.message,
                        "request_id": rid,
                        "running": False,
                        "last_emit_at": None,
                        "receiver_status": result.receiver_status,
                        "receiver_url": self.cfg.receiver_url,
                        "details": result.details,
                    },
                )
                return

            details = result.details or {}
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "status": "OK",
                    "message": "Estado consultado no receptor.",
                    "request_id": rid,
                    "running": bool(details.get("running", False)),
                    "last_emit_at": details.get("last_emit_at"),
                    "receiver_status": result.receiver_status,
                    "receiver_url": self.cfg.receiver_url,
                },
            )
            return

        if parsed.path != "/":
            self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
            return

        body = f"""
        <div class='info-row'>
          <span>Papel: <code>CONTROLADOR</code></span>
          <span>Host/porta: <code>{html.escape(self.cfg.bind)}:{self.cfg.port}</code></span>
          <span>Receptor alvo: <code>{html.escape(self.cfg.receiver_url)}</code></span>
          <span>Status: <span class='status-pill off' data-status>Parada</span></span>
          <span>Último acionamento: <strong data-last>—</strong></span>
        </div>
        <div class='grid'>
          <button class='btn primary' data-action='/emit'>Ligar Sirene</button>
          <button class='btn secondary' data-action='/stop'>Parar Sirene</button>
        </div>
        <div class='response' data-message>Pronto para enviar comandos ao receptor.</div>
        <div class='response'>
          Endpoints: <code>GET /status</code> | <code>POST /emit</code> | <code>POST /stop</code>
        </div>
        """
        page = layout_page(
            title="Controlador Central",
            subtitle="Painel remoto para emitir/parar a sirene.",
            banner_class="controller",
            banner_text="Você está no CONTROLADOR (comando remoto)",
            body_html=body,
            status_endpoint="/status",
        )
        self._write(HTTPStatus.OK, page)

    def do_POST(self) -> None:  # noqa: N802
        rid = self._new_request_id()
        parsed = self._parsed()

        if parsed.path not in {"/emit", "/stop"}:
            self._write(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
            return

        result = self._client().emit() if parsed.path == "/emit" else self._client().stop()
        if not result.ok:
            self._json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "ok": False,
                    "status": "Falha",
                    "message": result.message,
                    "request_id": rid,
                    "receiver_status": result.receiver_status,
                    "receiver_url": self.cfg.receiver_url,
                    "details": result.details,
                },
            )
            return

        last_emit = (result.details or {}).get("last_emit_at")
        status = "Ligada" if parsed.path == "/emit" else "Parada"
        self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "status": status,
                "message": result.message,
                "request_id": rid,
                "last_emit_at": last_emit,
                "receiver_status": result.receiver_status,
                "receiver_url": self.cfg.receiver_url,
            },
        )


# =========================
# Runtime helpers
# =========================

class NgrokManager:
    def __init__(self) -> None:
        self.processes: list[subprocess.Popen[bytes]] = []

    @staticmethod
    def _pick_tunnel_url(tunnels: list[dict[str, Any]], port: int) -> Optional[str]:
        """Seleciona o túnel que realmente aponta para a porta alvo.

        O endpoint do ngrok pode retornar vários túneis (inclusive antigos) e,
        se pegarmos sempre o primeiro, receptor e controlador podem receber o
        mesmo link por engano.
        """
        target_suffix = f":{port}"

        matched: list[dict[str, Any]] = []
        for tunnel in tunnels:
            cfg = tunnel.get("config") if isinstance(tunnel, dict) else None
            addr = cfg.get("addr", "") if isinstance(cfg, dict) else ""
            if isinstance(addr, str) and addr.endswith(target_suffix):
                matched.append(tunnel)

        if not matched:
            return None

        # Preferir HTTPS quando existir para compartilhamento externo.
        https = [t for t in matched if str(t.get("public_url", "")).startswith("https://")]
        chosen = https[0] if https else matched[0]
        public = chosen.get("public_url")
        return public if isinstance(public, str) else None

    def start_tunnel(self, port: int) -> Optional[str]:
        try:
            proc = subprocess.Popen(["ngrok", "http", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes.append(proc)
        except FileNotFoundError:
            LOG.warning("Ngrok não encontrado. Continuando sem túnel público.")
            return None

        endpoint = "http://127.0.0.1:4040/api/tunnels"
        for _ in range(24):
            try:
                with urllib.request.urlopen(endpoint, timeout=1) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                tunnels = data.get("tunnels", [])
                if isinstance(tunnels, list):
                    public = self._pick_tunnel_url(tunnels, port)
                    if public:
                        return public
            except (urllib.error.URLError, json.JSONDecodeError, socket.timeout):
                time.sleep(0.35)

        LOG.warning("Ngrok iniciou, mas URL pública da porta %s não foi detectada automaticamente.", port)
        return None

    def stop_all(self) -> None:
        for proc in self.processes:
            if proc.poll() is None:
                proc.terminate()


class ServerRuntime:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server

    def serve_forever(self) -> None:
        self.server.serve_forever()


# =========================
# CLI e execução
# =========================

@dataclass
class RuntimeConfig:
    mode: str
    bind: str
    receiver_port: int
    controller_port: int
    receiver_url: str
    token: Optional[str]
    ngrok: bool
    log_level: str


class AppServer:
    @staticmethod
    def start_receiver(cfg: RuntimeConfig, controller_url: Optional[str]) -> None:
        state = ReceiverState.create(cfg.token)
        receiver_cfg = ReceiverServerConfig(cfg.bind, cfg.receiver_port, cfg.token, controller_url)
        handler = type("ConfiguredReceiverHandler", (ReceiverHandler,), {"cfg": receiver_cfg, "state": state})
        server = ThreadingHTTPServer((cfg.bind, cfg.receiver_port), handler)
        LOG.info("Receptor ativo em http://%s:%d", cfg.bind, cfg.receiver_port)
        ServerRuntime(server).serve_forever()

    @staticmethod
    def start_controller(cfg: RuntimeConfig) -> None:
        controller_cfg = ControllerServerConfig(cfg.bind, cfg.controller_port, cfg.receiver_url, cfg.token)
        handler = type("ConfiguredControllerHandler", (ControllerHandler,), {"cfg": controller_cfg})
        server = ThreadingHTTPServer((cfg.bind, cfg.controller_port), handler)
        LOG.info("Controlador ativo em http://%s:%d", cfg.bind, cfg.controller_port)
        LOG.info("Controlador aponta para receptor: %s", cfg.receiver_url)
        ServerRuntime(server).serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sirene remota (arquivo único).")
    parser.add_argument("--mode", choices=["receiver", "controller", "both"], default=os.getenv("SIREN_MODE", "both"))
    parser.add_argument("--bind", default=os.getenv("SIREN_BIND", "0.0.0.0"))
    parser.add_argument("--receiver-port", type=int, default=int(os.getenv("SIREN_RECEIVER_PORT", "5001")))
    parser.add_argument("--controller-port", type=int, default=int(os.getenv("SIREN_CONTROLLER_PORT", "5000")))
    parser.add_argument("--receiver-url", default=os.getenv("SIREN_RECEIVER_URL", ""))
    parser.add_argument("--token", default=os.getenv("SIREN_TOKEN"))
    parser.add_argument("--ngrok", action="store_true", default=os.getenv("SIREN_NGROK", "1") == "1")
    parser.add_argument("--no-ngrok", action="store_true")
    parser.add_argument("--log-level", default=os.getenv("SIREN_LOG_LEVEL", "INFO"))
    return parser


def resolve_config(args: argparse.Namespace) -> RuntimeConfig:
    ngrok = bool(args.ngrok and not args.no_ngrok)

    receiver_port = args.receiver_port if args.receiver_port else find_available_port(5001)
    controller_port = args.controller_port if args.controller_port else find_available_port(5000)

    receiver_url = args.receiver_url.strip()
    if not receiver_url and args.mode in {"controller", "both"}:
        receiver_url = f"http://127.0.0.1:{receiver_port}"

    if args.mode == "controller" and not receiver_url:
        raise SystemExit("--receiver-url é obrigatório no modo controller")

    if args.mode == "controller":
        parsed = urllib.parse.urlparse(receiver_url)
        if parsed.hostname not in LOCALHOSTS and not args.token:
            LOG.warning("Controlador remoto sem token: isso é inseguro")

    return RuntimeConfig(
        mode=args.mode,
        bind=args.bind,
        receiver_port=receiver_port,
        controller_port=controller_port,
        receiver_url=receiver_url,
        token=args.token,
        ngrok=ngrok,
        log_level=args.log_level,
    )


def print_effective_config(cfg: RuntimeConfig) -> None:
    LOG.info("Configuração efetiva:")
    LOG.info("  mode=%s", cfg.mode)
    LOG.info("  bind=%s", cfg.bind)
    LOG.info("  receiver_port=%d", cfg.receiver_port)
    LOG.info("  controller_port=%d", cfg.controller_port)
    LOG.info("  receiver_url=%s", cfg.receiver_url)
    LOG.info("  token=%s", mask_secret(cfg.token))
    LOG.info("  ngrok=%s", cfg.ngrok)


def run_both(cfg: RuntimeConfig) -> None:
    ngrok_mgr = NgrokManager()
    receiver_public = None
    controller_public = None

    if cfg.ngrok:
        receiver_public = ngrok_mgr.start_tunnel(cfg.receiver_port)
        controller_public = ngrok_mgr.start_tunnel(cfg.controller_port)

    local_ip = detect_local_ip()
    LOG.info("Inicialização modo BOTH")
    LOG.info("Receptor local: http://localhost:%d", cfg.receiver_port)
    LOG.info("Controlador local: http://localhost:%d", cfg.controller_port)
    if local_ip not in LOCALHOSTS:
        LOG.info("Receptor na rede local: http://%s:%d", local_ip, cfg.receiver_port)
        LOG.info("Controlador na rede local: http://%s:%d", local_ip, cfg.controller_port)
    if receiver_public:
        LOG.info("Receptor público (ngrok): %s", receiver_public)
    if controller_public:
        LOG.info("Controlador público (ngrok): %s", controller_public)

    def _shutdown(*_: Any) -> None:
        LOG.info("Encerrando...")
        ngrok_mgr.stop_all()
        os._exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    receiver_thread = threading.Thread(
        target=AppServer.start_receiver,
        args=(cfg, controller_public or f"http://127.0.0.1:{cfg.controller_port}"),
        daemon=True,
        name="receiver-server",
    )
    receiver_thread.start()
    time.sleep(0.5)

    AppServer.start_controller(cfg)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)
    cfg = resolve_config(args)
    print_effective_config(cfg)

    if cfg.mode == "receiver":
        AppServer.start_receiver(cfg, controller_url=None)
        return
    if cfg.mode == "controller":
        AppServer.start_controller(cfg)
        return
    run_both(cfg)


if __name__ == "__main__":
    main()
