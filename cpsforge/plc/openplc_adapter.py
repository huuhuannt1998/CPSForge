"""
cpsforge.plc.openplc_adapter
==============================
REST API client for managing OpenPLC Runtime v4.

Provides programmatic control over the OpenPLC lifecycle:
  - Upload ST / IEC 61131-3 programs
  - Compile programs on the runtime
  - Start / stop PLC execution
  - Monitor compilation status and runtime logs

This adapter is used by the logic analysis runner (Tier 3) to
automatically deploy LLM-generated ST programs to a live PLC runtime
and observe the effects.

OpenPLC v4 REST API (port 8443, HTTPS with self-signed cert):
  POST /api/create-user       — First user creation (no auth)
  POST /api/login             — Returns JWT token
  POST /api/upload-file       — Upload program ZIP
  GET  /api/compilation-status — Poll compilation progress
  GET  /api/start-plc         — Start PLC execution
  GET  /api/stop-plc          — Stop PLC execution
  GET  /api/status            — Runtime status
  GET  /api/runtime-logs      — Get runtime logs
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class OpenPLCConfig:
    """Connection configuration for OpenPLC Runtime v4."""
    host: str = "127.0.0.1"
    port: int = 8443
    username: str = "openplc"
    password: str = "openplc"
    use_tls: bool = True
    verify_tls: bool = False     # Self-signed cert by default
    timeout_s: float = 30.0
    compile_poll_interval_s: float = 2.0
    compile_timeout_s: float = 120.0

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}"

    @classmethod
    def from_dict(cls, data: dict) -> "OpenPLCConfig":
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


@dataclass
class CompilationResult:
    """Result of an OpenPLC program compilation."""
    success: bool
    logs: str = ""
    error: str = ""


@dataclass
class RuntimeStatus:
    """Current state of the OpenPLC runtime."""
    running: bool = False
    program_loaded: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


class OpenPLCAdapter:
    """
    REST client for OpenPLC Runtime v4.

    Manages the full lifecycle: authenticate → upload → compile → run.

    Usage
    -----
    adapter = OpenPLCAdapter(OpenPLCConfig())
    adapter.authenticate()
    result = adapter.upload_and_compile(st_code="PROGRAM main ... END_PROGRAM")
    if result.success:
        adapter.start_plc()
        # ... run experiment ...
        adapter.stop_plc()
    """

    def __init__(self, config: OpenPLCConfig) -> None:
        self._config = config
        self._token: Optional[str] = None
        self._session = None

    # ------------------------------------------------------------------
    # Lazy requests import
    # ------------------------------------------------------------------

    @staticmethod
    def _get_requests():
        try:
            import requests
            return requests
        except ImportError as exc:
            raise ImportError(
                "requests is not installed. "
                "Install it with: pip install requests"
            ) from exc

    def _get_session(self):
        if self._session is None:
            requests = self._get_requests()
            self._session = requests.Session()
            self._session.verify = self._config.verify_tls
            # Suppress InsecureRequestWarning for self-signed certs
            if not self._config.verify_tls:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return self._session

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _url(self, path: str) -> str:
        return f"{self._config.base_url}{path}"

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Login to OpenPLC and obtain a JWT token.

        On first run, creates the initial user account if no users exist.
        """
        session = self._get_session()

        # Check if we need to create the first user
        try:
            resp = session.get(
                self._url("/api/get-users-info"),
                timeout=self._config.timeout_s,
            )
            if resp.status_code == 200:
                users = resp.json()
                if not users or (isinstance(users, list) and len(users) == 0):
                    self._create_first_user(session)
        except Exception:
            # If endpoint fails, try creating user anyway
            self._create_first_user(session)

        # Login
        resp = session.post(
            self._url("/api/login"),
            json={
                "username": self._config.username,
                "password": self._config.password,
            },
            timeout=self._config.timeout_s,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("access_token") or data.get("token")
        if not self._token:
            raise RuntimeError(f"Login succeeded but no token in response: {data}")
        logger.info("Authenticated with OpenPLC at %s", self._config.base_url)

    def _create_first_user(self, session) -> None:
        """Create the initial admin user on a fresh OpenPLC instance."""
        try:
            resp = session.post(
                self._url("/api/create-user"),
                json={
                    "username": self._config.username,
                    "password": self._config.password,
                },
                timeout=self._config.timeout_s,
            )
            if resp.status_code in (200, 201):
                logger.info("Created initial OpenPLC user: %s",
                            self._config.username)
            else:
                logger.debug("create-user returned %d (user may already exist)",
                             resp.status_code)
        except Exception as exc:
            logger.debug("Could not create first user: %s", exc)

    # ------------------------------------------------------------------
    # Program upload and compilation
    # ------------------------------------------------------------------

    def upload_and_compile(
        self,
        st_code: Optional[str] = None,
        st_file: Optional[Path] = None,
        program_name: str = "cpsforge_program",
    ) -> CompilationResult:
        """
        Upload an ST program and compile it on the OpenPLC runtime.

        Provide either ``st_code`` (string) or ``st_file`` (path).
        The method packages the ST file into a ZIP as required by the
        OpenPLC upload API, uploads it, and polls for compilation status.

        Parameters
        ----------
        st_code:
            Raw Structured Text program source code.
        st_file:
            Path to a .st file on disk.
        program_name:
            Name for the program inside the ZIP archive.

        Returns
        -------
        CompilationResult
            Contains success flag, compilation logs, and any error message.
        """
        if st_code is None and st_file is None:
            raise ValueError("Provide either st_code or st_file")

        if st_code is None:
            st_code = Path(st_file).read_text(encoding="utf-8")

        self._ensure_authenticated()

        # Package ST code into a ZIP (OpenPLC expects multipart/form-data with .zip)
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{program_name}.st", st_code)
        zip_buffer.seek(0)

        session = self._get_session()

        # Upload
        resp = session.post(
            self._url("/api/upload-file"),
            headers={"Authorization": f"Bearer {self._token}"},
            files={"file": (f"{program_name}.zip", zip_buffer, "application/zip")},
            timeout=self._config.timeout_s,
        )
        if resp.status_code not in (200, 201, 202):
            return CompilationResult(
                success=False,
                error=f"Upload failed ({resp.status_code}): {resp.text}",
            )
        logger.info("Program uploaded to OpenPLC: %s", program_name)

        # Poll compilation status
        return self._poll_compilation()

    def _poll_compilation(self) -> CompilationResult:
        """Poll /api/compilation-status until complete or timeout."""
        import time
        session = self._get_session()
        deadline = time.monotonic() + self._config.compile_timeout_s

        while time.monotonic() < deadline:
            resp = session.get(
                self._url("/api/compilation-status"),
                headers=self._headers(),
                timeout=self._config.timeout_s,
            )
            if resp.status_code != 200:
                return CompilationResult(
                    success=False,
                    error=f"compilation-status returned {resp.status_code}",
                )

            data = resp.json()
            status = data.get("status", "").lower()

            if status in ("success", "done", "complete", "compiled"):
                logger.info("OpenPLC compilation succeeded.")
                return CompilationResult(
                    success=True,
                    logs=data.get("logs", ""),
                )
            elif status in ("error", "failed", "failure"):
                return CompilationResult(
                    success=False,
                    logs=data.get("logs", ""),
                    error=data.get("error", "Compilation failed"),
                )
            # Still compiling — wait and retry
            time.sleep(self._config.compile_poll_interval_s)

        return CompilationResult(
            success=False,
            error=f"Compilation timed out after {self._config.compile_timeout_s}s",
        )

    # ------------------------------------------------------------------
    # PLC execution control
    # ------------------------------------------------------------------

    def start_plc(self) -> bool:
        """Start PLC program execution. Returns True on success."""
        self._ensure_authenticated()
        session = self._get_session()
        resp = session.get(
            self._url("/api/start-plc"),
            headers=self._headers(),
            timeout=self._config.timeout_s,
        )
        success = resp.status_code == 200
        if success:
            logger.info("OpenPLC started.")
        else:
            logger.error("Failed to start OpenPLC: %d %s",
                         resp.status_code, resp.text)
        return success

    def stop_plc(self) -> bool:
        """Stop PLC program execution. Returns True on success."""
        self._ensure_authenticated()
        session = self._get_session()
        resp = session.get(
            self._url("/api/stop-plc"),
            headers=self._headers(),
            timeout=self._config.timeout_s,
        )
        success = resp.status_code == 200
        if success:
            logger.info("OpenPLC stopped.")
        else:
            logger.error("Failed to stop OpenPLC: %d %s",
                         resp.status_code, resp.text)
        return success

    def get_status(self) -> RuntimeStatus:
        """Get current runtime status."""
        self._ensure_authenticated()
        session = self._get_session()
        try:
            resp = session.get(
                self._url("/api/status"),
                headers=self._headers(),
                timeout=self._config.timeout_s,
            )
            if resp.status_code == 200:
                data = resp.json()
                return RuntimeStatus(
                    running=data.get("running", False),
                    program_loaded=data.get("program_loaded", False),
                    raw=data,
                )
        except Exception as exc:
            logger.warning("Failed to get OpenPLC status: %s", exc)
        return RuntimeStatus()

    def get_logs(self, lines: int = 100) -> str:
        """Retrieve recent runtime logs."""
        self._ensure_authenticated()
        session = self._get_session()
        try:
            resp = session.get(
                self._url("/api/runtime-logs"),
                headers=self._headers(),
                timeout=self._config.timeout_s,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("logs", str(data))
        except Exception as exc:
            logger.warning("Failed to get OpenPLC logs: %s", exc)
        return ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_authenticated(self) -> None:
        if self._token is None:
            self.authenticate()
