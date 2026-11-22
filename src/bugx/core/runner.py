
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class ToolResult:
    tool: str
    success: bool
    returncode: Optional[int]
    stdout: str
    stderr: str
    error: Optional[str] = None
    duration: float = 0.0


class ToolRunner:
    """Common execution interface for BUGX tools."""

    @staticmethod
    def is_installed(tool_name: str) -> bool:
        """Check whether a tool exists in system PATH."""
        return shutil.which(tool_name) is not None

    @staticmethod
    def get_path(tool_name: str) -> Optional[str]:
        """Return the executable path."""
        return shutil.which(tool_name)

    @staticmethod
    def run(
        tool_name: str,
        args: list,
        timeout: int = 180,
        input_text: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> ToolResult:
        """Execute an installed command-line tool.

        ``input_text`` is written to stdin; otherwise stdin is closed so a
        tool can never block waiting for interactive input (e.g. sudo).
        """

        executable = shutil.which(tool_name)

        if not executable:
            return ToolResult(
                tool=tool_name,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                error=f"{tool_name} is not installed or not in PATH.",
            )

        command = [executable, *map(str, args)]
        started = time.monotonic()

        stdin_kwargs = (
            {"input": input_text}
            if input_text is not None
            else {"stdin": subprocess.DEVNULL}
        )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                shell=False,
                cwd=cwd,
                **stdin_kwargs,
            )

            return ToolResult(
                tool=tool_name,
                success=result.returncode == 0,
                returncode=result.returncode,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                duration=round(time.monotonic() - started, 3),
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool_name,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                error=f"{tool_name} timed out after {timeout} seconds.",
                duration=round(time.monotonic() - started, 3),
            )

        except OSError as exc:
            return ToolResult(
                tool=tool_name,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                error=str(exc),
            )
