"""Where in the code an error was thrown, read from its stack trace.

For each event with a stack trace this finds the exception type and the frame in the
application's own code closest to where it was thrown (framework and library frames are
skipped). Two errors logged with the same message ("Unhandled exception in circuit") but
thrown from different places are different problems, and the place is what a developer
opens next.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .parser import LogRecord

# .NET: "at Ns.Type.Method(Args) in D:\src\File.cs:line 129"
_DOTNET = re.compile(r"\bat (?P<method>[^\s(]+)\([^)\n]*\) in (?P<file>[^\n]+?):line (?P<line>\d+)")
# Java / Kotlin: "at com.shop.Orders.save(Orders.java:88)"
_JAVA = re.compile(r"\bat (?P<method>[\w.$<>]+)\((?P<file>[\w$-]+\.(?:java|kt|scala|groovy)):(?P<line>\d+)\)")
# Python: 'File "/app/worker/tasks.py", line 88, in resize_image'
_PYTHON = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<method>\S+)')
# Node: "at uploadHandler (/app/src/routes/uploads.js:44:9)" or "at /app/src/x.js:3:1"
_NODE = re.compile(r"\bat (?:(?P<method>[\w.<>$\[\] ]+?) \()?(?P<file>[^\s()]+\.(?:js|mjs|cjs|ts|tsx|jsx)):(?P<line>\d+):\d+\)?")

_LIBRARY = re.compile(
    r"^(?:System\.|Microsoft\.|Windows\.|Newtonsoft\.|Serilog\.|Polly\.|Grpc\.|java\.|javax\.|jakarta\.|jdk\.|sun\.|"
    r"com\.sun\.|kotlin\.|kotlinx\.|scala\.|org\.springframework\.|org\.hibernate\.|org\.apache\.|com\.zaxxer\.|"
    r"io\.netty\.|reactor\.|lambda\$)"
)
_LIBRARY_PATH = re.compile(r"node_modules|site-packages|dist-packages|[\\/]lib[\\/]python\d|<frozen|^internal[\\/]|^node:")
_EXCEPTION = re.compile(r"\b((?:[A-Za-z_]\w*\.)*[A-Z]\w*(?:Exception|Error))\b(?=[:,\s\"]|$)")


@dataclass(frozen=True, slots=True)
class CodeLocation:
    exception: str   # short name, e.g. NullReferenceException
    file: str        # as written in the stack trace (a full path when the trace has one)
    line: int
    method: str

    @property
    def short(self) -> str:
        name = re.split(r"[\\/]", self.file)[-1]
        return f"{self.exception + ' at ' if self.exception else ''}{name}:L{self.line}"


def _own(method: str, file: str) -> bool:
    return not _LIBRARY.match(method or "") and not _LIBRARY_PATH.search(file)


def code_location(record: LogRecord) -> CodeLocation | None:
    """The exception and the first frame in the application's own code, or None without a stack trace."""
    if not record.detail:
        return None
    # Some layouts write line breaks inside the trace as "[CRLF]".
    text = "\n".join(record.detail[:200]).replace("[CRLF]", "\n")
    frames: list[tuple[str, str, int]] = []
    python = False
    for pattern in (_DOTNET, _JAVA, _NODE, _PYTHON):
        found = [(m.group("method") or "", m.group("file"), int(m.group("line"))) for m in pattern.finditer(text)]
        if found:
            frames = found
            python = pattern is _PYTHON
            break
    own = [f for f in frames if _own(f[0], f[1])]
    if not own:
        return None
    # Python prints the outermost call first; the others print the innermost first.
    method, file, line = own[-1] if python else own[0]
    # Prefer full names ("System.NullReferenceException") over words that only look like one
    # ("CircuitUnhandledException" as an event name).
    names = _EXCEPTION.findall(text + "\n" + record.message)
    names = [n for n in names if "." in n] or names
    exception =(names[-1] if python else names[0]).split(".")[-1] if names else ""
    return CodeLocation(exception=exception, file=file.strip(), line=line, method=method)
