"""
CPSForge Structured Logger
============================
Sets up Python's stdlib logging with Rich for console output and a
JSON file handler for structured log persistence.

Call :func:`setup_logging` once at application startup (typically in main.py
or the CLI entry-point) before any module-level logger calls.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

# Rich is an optional soft dependency for pretty console output.
try:
    from rich.logging import RichHandler
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


class _JsonFileHandler(logging.FileHandler):
    """Emits each log record as a JSON line to a file."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_entry = {
                "timestamp": self.formatter.formatTime(record) if self.formatter else record.asctime,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "line": record.lineno,
            }
            if record.exc_info:
                log_entry["exc_info"] = self.formatter.formatException(record.exc_info)
            self.stream.write(json.dumps(log_entry) + "\n")
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    use_rich: bool = True,
    run_id: Optional[str] = None,
) -> None:
    """
    Configure root and cpsforge loggers.

    Parameters
    ----------
    level:
        Logging level string: DEBUG, INFO, WARNING, ERROR.
    log_dir:
        If provided, a JSON log file is written to ``<log_dir>/cpsforge.log``.
    use_rich:
        Use Rich coloured console handler if available.
    run_id:
        Optional run ID appended to log file name.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    # Console handler
    if use_rich and _RICH_AVAILABLE:
        console_handler = RichHandler(
            level=log_level,
            rich_tracebacks=True,
            markup=False,
            show_path=False,
        )
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    handlers.append(console_handler)

    # JSON file handler
    if log_dir is not None:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        fname = f"cpsforge_{run_id}.log" if run_id else "cpsforge.log"
        file_handler = _JsonFileHandler(log_dir / fname, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter())
        handlers.append(file_handler)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    # Remove any pre-existing handlers
    for h in root.handlers[:]:
        root.removeHandler(h)
    for h in handlers:
        root.addHandler(h)

    # Silence noisy third-party loggers
    logging.getLogger("snap7").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
