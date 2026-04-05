"""Nmap skill – wraps the nmap command-line tool for network scanning."""

import shlex
import subprocess
from typing import Any

from .base_skill import BaseSkill


class NmapSkill(BaseSkill):
    """Skill that runs an nmap scan against a target host or CIDR range.

    The skill requires the ``nmap`` binary to be present on ``PATH``.
    All arguments are validated and shell-injection is prevented by using
    ``subprocess`` with a list of arguments (no shell=True).

    Example::

        skill = NmapSkill()
        result = skill.execute(target="192.168.1.0/24", flags=["-sV", "-T4"])
    """

    # Allowed nmap flag prefixes – blocks dangerous flags like --script or -oX
    _ALLOWED_FLAG_PREFIXES = (
        "-sS", "-sT", "-sU", "-sV", "-sC",
        "-A", "-O",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-p", "--top-ports",
        "-Pn", "-n",
        "--open",
    )

    def __init__(self) -> None:
        super().__init__(
            name="nmap",
            description="Run an nmap scan against a target host or network range.",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_target(target: str) -> None:
        """Reject targets that look like shell injection attempts."""
        forbidden = (";", "&", "|", "`", "$", "(", ")", "\n", "\r", " ")
        for ch in forbidden:
            if ch in target:
                raise ValueError(f"Invalid character {ch!r} in nmap target: {target!r}")

    def _validate_flags(self, flags: list[str]) -> None:
        for flag in flags:
            # Each element must start with one of the allowed prefixes
            if not any(flag == prefix or flag.startswith(prefix) for prefix in self._ALLOWED_FLAG_PREFIXES):
                raise ValueError(f"nmap flag not allowed: {flag!r}")

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    def execute(self, target: str, flags: list[str] | None = None, timeout: int = 120) -> dict[str, Any]:
        """Run nmap against *target*.

        Args:
            target: Hostname, IP address or CIDR range to scan.
            flags:  Optional list of nmap flags (e.g. ``["-sV", "-T4"]``).
                    Only a safe subset of flags is permitted.
            timeout: Maximum seconds to wait for nmap to complete.

        Returns:
            ``{"skill": "nmap", "status": "success"/"error", "result": <output>}``
        """
        if not target:
            raise ValueError("target must not be empty")

        self._validate_target(target)
        flags = flags or ["-sV", "-T4"]
        self._validate_flags(flags)

        cmd = ["nmap"] + flags + [target]
        self.logger.info("Running: %s", shlex.join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode != 0:
                return {
                    "skill": self.name,
                    "status": "error",
                    "result": proc.stderr.strip() or proc.stdout.strip(),
                }
            return {
                "skill": self.name,
                "status": "success",
                "result": proc.stdout.strip(),
            }
        except FileNotFoundError:
            return {
                "skill": self.name,
                "status": "error",
                "result": "nmap binary not found on PATH",
            }
        except subprocess.TimeoutExpired:
            return {
                "skill": self.name,
                "status": "error",
                "result": f"nmap scan timed out after {timeout}s",
            }
