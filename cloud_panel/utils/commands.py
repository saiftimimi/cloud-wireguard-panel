"""Safe subprocess helpers used by Cloud WG Panel."""

import subprocess
from typing import Optional, Sequence


def run(
    cmd: Sequence[str],
    input_text: Optional[str] = None,
    check: bool = True,
) -> str:
    """Run a command and return decoded stdout.

    This preserves the behavior of the legacy app.py helper.
    """
    try:
        proc = subprocess.run(
            list(cmd),
            input=input_text.encode() if input_text else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as exc:
        if check:
            executable = str(cmd[0]) if cmd else "Command"
            raise RuntimeError(
                "%s is unavailable: %s" % (executable, exc)
            ) from exc
        return ""

    if check and proc.returncode != 0:
        message = proc.stderr.decode(
            errors="ignore"
        ).strip() or "Command failed"
        raise RuntimeError(message)

    return proc.stdout.decode(errors="ignore").strip()
