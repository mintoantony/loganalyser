"""Known failure signatures.

Each rule names a cause a person would recognise, the log text that gives it
away, and what to do about it. ``rootness`` says how often the signature is
the origin of an incident rather than a knock-on effect: running out of
memory is usually where trouble starts (high), an HTTP 502 almost never is
(low). The ranking in analysis.py uses it to tell causes from symptoms.

Extra rules can be loaded from a JSON file with the same fields
(see ``load_rules``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    category: str
    patterns: list[str]
    rootness: float
    explanation: str
    fixes: list[str]
    compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    custom: bool = False

    def __post_init__(self) -> None:
        self.compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.patterns]

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.compiled)


def _r(id, title, category, rootness, patterns, explanation, fixes) -> Rule:
    return Rule(id=id, title=title, category=category, patterns=patterns, rootness=rootness,
                explanation=explanation, fixes=fixes)


BUILTIN_RULES: list[Rule] = [
    # Resources
    _r("oom", "Process ran out of memory", "Resources", 0.95,
       [r"OutOfMemoryError", r"\bout of memory\b", r"Cannot allocate memory", r"MemoryError\b",
        r"OOMKilled", r"oom-kill", r"Killed process \d+", r"JavaScript heap out of memory",
        r"GC overhead limit exceeded", r"std::bad_alloc"],
       "The process could not get more memory, so it failed or was killed by the system.",
       ["Check memory use over time for a leak (growing heap, caches without limits).",
        "Raise the memory limit (-Xmx, container limit) only after ruling out a leak.",
        "Look at what ran just before: a large request, batch job or query result."]),
    _r("disk_full", "Disk is full", "Resources", 0.95,
       [r"No space left on device", r"disk (?:is )?full", r"ENOSPC", r"Disk quota exceeded",
        r"could not extend file", r"insufficient disk space"],
       "Writes failed because the disk or volume has no free space left.",
       ["Free space or grow the volume.", "Rotate and compress logs; remove old temp files.",
        "Add a disk-usage alert well before 100%."]),
    _r("fd_limit", "Too many open files", "Resources", 0.85,
       [r"Too many open files", r"EMFILE", r"file descriptor(?:s)? (?:limit|exhausted)"],
       "The process hit its limit on open files or sockets, usually because connections or files are not closed.",
       ["Raise ulimit -n if the load is legitimate.",
        "Look for connections, streams or files that are opened but never closed."]),
    _r("thread_exhaustion", "Thread pool exhausted", "Resources", 0.75,
       [r"unable to create (?:new )?native thread", r"RejectedExecutionException",
        r"thread pool (?:is )?(?:exhausted|full)", r"all threads (?:are )?busy", r"Thread starvation"],
       "No worker threads were free to take new work, so requests were rejected or queued.",
       ["Find what is holding threads (slow downstream calls, locks).",
        "Add timeouts to outgoing calls so threads are released."]),
    _r("cpu_throttle", "CPU starvation or throttling", "Resources", 0.55,
       [r"CPU throttl", r"load average (?:is )?(?:too )?high", r"watchdog: BUG: soft lockup",
        r"Starvation detected", r"blocked for more than \d+ seconds"],
       "The process did not get enough CPU time, so work stalled.",
       ["Check CPU limits and noisy neighbours.", "Profile hot code paths."]),

    # Database
    _r("db_pool", "Database connection pool exhausted", "Database", 0.9,
       [r"Connection is not available, request timed out", r"connection pool (?:is )?(?:exhausted|full)",
        r"(?:Cannot|Unable to) (?:get|acquire|obtain) (?:a )?(?:JDBC )?connection",
        r"pool (?:is )?exhausted", r"remaining connection slots are reserved",
        r"too many (?:connections|clients)", r"max_connections", r"QueuePool limit of size \d+",
        r"active=\d+,? idle=0", r"waiting=\d{2,}"],
       "Every database connection was in use, so new work had to wait and then timed out.",
       ["Find what holds connections for a long time (long transactions, a batch job, leaks).",
        "Make sure connections are returned to the pool on every code path.",
        "Size the pool against the database's max_connections, across all instances."]),
    _r("db_deadlock", "Database deadlock", "Database", 0.75,
       [r"deadlock detected", r"Deadlock found", r"DeadlockLoserDataAccessException",
        r"was deadlocked on lock resources", r"ORA-00060"],
       "Two transactions waited on each other's locks and the database aborted one.",
       ["Access tables in the same order in every transaction.", "Keep transactions short.",
        "Retry the aborted transaction."]),
    _r("db_lock_timeout", "Database lock wait timeout", "Database", 0.7,
       [r"Lock wait timeout exceeded", r"lock timeout", r"canceling statement due to lock timeout",
        r"could not obtain lock"],
       "A query waited too long for a lock held by another transaction.",
       ["Find the blocking transaction (pg_locks, SHOW ENGINE INNODB STATUS).",
        "Shorten long-running transactions."]),
    _r("db_down", "Database unreachable", "Database", 0.8,
       [r"(?:database|db|postgres|mysql|mongo\w*|redis|sql server)\S* (?:is )?(?:down|unavailable|unreachable)",
        r"Communications link failure", r"could not connect to server", r"the database system is "
        r"(?:starting up|shutting down|in recovery mode)", r"Connection to \S+ refused.*postgres",
        r"MongoServerSelectionError", r"ORA-12541", r"Can't connect to MySQL server"],
       "The application could not reach its database at all.",
       ["Check that the database is running and accepting connections.",
        "Check network and firewall rules between the app and the database.",
        "Check credentials and the connection string."]),
    _r("db_slow", "Slow database queries", "Database", 0.6,
       [r"slow query", r"duration: \d{4,}(?:\.\d+)? ms", r"Query took \d{4,}\s?ms",
        r"statement timeout", r"canceling statement due to statement timeout", r"Query execution was interrupted"],
       "Queries took much longer than usual, holding connections and slowing everything behind them.",
       ["Run EXPLAIN on the slow statement; look for missing indexes.",
        "Check for a recent data growth or a plan change."]),
    _r("db_constraint", "Data constraint violation", "Database", 0.45,
       [r"duplicate key value violates unique constraint", r"Duplicate entry .* for key",
        r"violates foreign key constraint", r"IntegrityError", r"ConstraintViolationException",
        r"null value in column .* violates not-null constraint"],
       "A write broke a database rule (unique key, foreign key, not-null).",
       ["Check the input that produced the write.", "Make the write idempotent if it can be retried."]),

    # Network
    _r("conn_refused", "Connection refused", "Network", 0.6,
       [r"Connection refused", r"ECONNREFUSED", r"actively refused"],
       "Nothing was listening at the address the client connected to: the service is down or on another port.",
       ["Check that the target service is up and listening on the expected port.",
        "Check service discovery or DNS records for a stale address."]),
    _r("timeout", "Calls timing out", "Network", 0.35,
       [r"\btimed? ?out\b", r"TimeoutException", r"ETIMEDOUT", r"deadline exceeded",
        r"Read timed out", r"context deadline exceeded", r"504 Gateway Time-?out", r"SocketTimeoutException"],
       "Calls waited longer than their limit. Timeouts are usually a symptom of something slow further down.",
       ["Follow the call to the service it waited on and look at that service's logs at the same time.",
        "Check that timeouts get shorter at each hop, so callers do not outwait their callees."]),
    _r("conn_reset", "Connection reset or broken", "Network", 0.4,
       [r"Connection reset", r"ECONNRESET", r"Broken pipe", r"EPIPE", r"connection (?:was )?closed by peer",
        r"Unexpected end of (?:file|stream)", r"EOFException"],
       "The other side closed the connection while it was in use.",
       ["Look for the peer restarting or crashing at the same time.",
        "Check idle timeouts on load balancers and pooled connections."]),
    _r("dns", "DNS lookup failed", "Network", 0.8,
       [r"UnknownHostException", r"Name or service not known", r"getaddrinfo (?:ENOTFOUND|EAI_AGAIN)",
        r"no such host", r"Temporary failure in name resolution", r"could not resolve host"],
       "A host name could not be turned into an address.",
       ["Check the host name for typos and that the DNS record exists.",
        "Check the resolver (resolv.conf, cluster DNS) is reachable."]),
    _r("tls", "TLS / certificate error", "Network", 0.85,
       [r"certificate (?:has )?expired", r"SSLHandshakeException", r"CERTIFICATE_VERIFY_FAILED",
        r"x509: certificate", r"unable to find valid certification path", r"self[- ]signed certificate",
        r"SSL routines", r"handshake failure"],
       "A secure connection could not be set up because of a certificate or protocol problem.",
       ["Check the certificate expiry date and chain.", "Check the trust store includes the issuing CA.",
        "Check both sides support a common TLS version."]),
    _r("port_in_use", "Port already in use", "Configuration", 0.9,
       [r"Address already in use", r"EADDRINUSE", r"BindException", r"port \d+ (?:is )?already in use"],
       "The service could not start listening because another process already holds the port.",
       ["Find the process holding the port (netstat / ss / lsof) and stop it, or change the port."]),

    # Upstream / dependencies
    _r("upstream_5xx", "Upstream service returning errors", "Dependencies", 0.25,
       [r"\b50[0234]\b.*(?:upstream|from|response|status)", r"(?:status|code)[=: ]+50[0234]\b",
        r"502 Bad Gateway", r"503 Service Unavailable", r"upstream (?:prematurely closed|timed out|connect error)",
        r"no healthy upstream"],
       "A service further down the chain answered with a server error.",
       ["Open the upstream service's logs at the same minute; the cause is usually there."]),
    _r("http_5xx", "Requests failing with server errors", "Dependencies", 0.15,
       [r"^[A-Z]+ \S+ 5\d\d$"],
       "Clients received 5xx responses. This is what users see, rarely why it happens.",
       ["Match the failing requests to the backend logs at the same time (see Linked requests)."]),
    _r("circuit_open", "Circuit breaker open", "Dependencies", 0.3,
       [r"circuit ?breaker.*(?:open|OPEN)", r"CallNotPermittedException", r"Hystrix.*short-circuited"],
       "A circuit breaker stopped calls to a dependency after too many failures.",
       ["Look for why the dependency failed before the breaker opened."]),
    _r("rate_limited", "Rate limited", "Dependencies", 0.5,
       [r"\b429\b", r"Too Many Requests", r"rate limit(?:ed| exceeded)", r"throttl(?:ed|ing) request",
        r"quota exceeded"],
       "A service refused requests because the caller sent too many too quickly.",
       ["Add backoff and retry with jitter.", "Check for a retry storm amplifying traffic."]),
    _r("queue_backlog", "Message queue backing up", "Dependencies", 0.55,
       [r"consumer lag", r"queue (?:is )?full", r"backlog", r"message(?:s)? (?:rejected|dropped)",
        r"Dead letter", r"buffer (?:is )?full"],
       "Messages arrived faster than they were processed.",
       ["Check consumer health and throughput.", "Look for a slow downstream call inside the consumer."]),

    # Security / access
    _r("auth", "Authentication failing", "Security", 0.6,
       [r"\b401\b.*(?:Unauthorized|auth)", r"Unauthorized", r"invalid (?:credentials|token|api key|password)",
        r"authentication failed", r"token (?:has )?expired", r"JWT expired", r"login failed",
        r"password authentication failed"],
       "Requests were rejected because credentials were missing, wrong or expired.",
       ["Check whether a secret or token was rotated or expired.",
        "Check the clock on both machines; skew breaks token validation."]),
    _r("permission", "Permission denied", "Security", 0.75,
       [r"Permission denied", r"EACCES", r"AccessDenied", r"\b403\b.*Forbidden", r"access is denied",
        r"Operation not permitted", r"insufficient privileges"],
       "The process was not allowed to read, write or call something it needed.",
       ["Check file ownership and modes, or the role / policy the service runs as.",
        "Look for a recent change to permissions or the service account."]),

    # Configuration
    _r("config_missing", "Missing or invalid configuration", "Configuration", 0.85,
       [r"(?:config|configuration|property|setting|env(?:ironment)? var\w*)\S* .*(?:not (?:set|found|defined)|missing|invalid)",
        r"Could not resolve placeholder", r"KeyError: '[A-Z_]{3,}'", r"is not set", r"No such file or directory.*\.(?:ya?ml|json|conf|ini|properties|env)",
        r"Failed to load (?:config|configuration|properties)"],
       "The service started without a setting it needs, or with one it cannot read.",
       ["Compare the configuration with the last working deployment.",
        "Check environment variables and mounted config files exist in this environment."]),
    _r("file_missing", "File not found", "Configuration", 0.6,
       [r"FileNotFoundException", r"No such file or directory", r"ENOENT", r"cannot find the (?:file|path)"],
       "A file the process expected was not there.",
       ["Check the path, the working directory and mounted volumes."]),
    _r("class_missing", "Missing code or dependency", "Configuration", 0.85,
       [r"ClassNotFoundException", r"NoClassDefFoundError", r"ModuleNotFoundError", r"ImportError",
        r"Cannot find module", r"NoSuchMethodError", r"undefined symbol", r"DLL load failed"],
       "Code the service needed was not on the classpath or installed, often after a build or dependency change.",
       ["Compare the built artifact's dependencies with the last good version.",
        "Look for two versions of one library."]),
    _r("startup_failure", "Service failed to start", "Runtime", 0.8,
       [r"Application run failed", r"failed to start", r"Startup failed", r"BeanCreationException",
        r"UnsatisfiedDependencyException", r"Error starting ApplicationContext", r"exited with code [1-9]"],
       "The service stopped during startup, so it never served traffic.",
       ["Read the first error in the startup sequence; later ones are knock-on."]),

    # Runtime / application
    _r("crash", "Process crashed", "Runtime", 0.85,
       [r"Segmentation fault", r"SIGSEGV", r"SIGABRT", r"core dumped", r"fatal error: runtime",
        r"panic:", r"Unhandled exception", r"terminate called after throwing", r"A fatal error has been detected"],
       "The process ended abruptly because of a crash in its own code or a native library.",
       ["Read the stack trace from the crash.", "Check for a recent deploy or native library upgrade."]),
    _r("restart_loop", "Service restarting repeatedly", "Runtime", 0.5,
       [r"CrashLoopBackOff", r"Back-off restarting failed container", r"restart(?:ed|ing) \d+ times",
        r"Liveness probe failed", r"Readiness probe failed", r"health ?check failed"],
       "The service keeps stopping and being restarted, often failing health checks.",
       ["Look at the logs from just before each restart for the real error."]),
    _r("null_ref", "Null reference in code", "Application", 0.65,
       [r"NullPointerException", r"NullReferenceException", r"Cannot read propert(?:y|ies) of (?:undefined|null)",
        r"'NoneType' object", r"undefined is not an object", r"nil pointer dereference"],
       "Code used a value that was empty. Usually a bug, or unexpected input from another system.",
       ["Open the top of the stack trace and find which value was empty.",
        "Check whether an upstream response changed shape."]),
    _r("bad_input", "Invalid data or parsing failure", "Application", 0.55,
       [r"JsonParseException", r"JSONDecodeError", r"Unexpected token", r"NumberFormatException",
        r"ValueError", r"invalid (?:input|format|json|argument)", r"IllegalArgumentException",
        r"deserializ\w* (?:error|failed)", r"SerializationException"],
       "Code received data it could not understand.",
       ["Capture one failing payload and compare it with a good one.",
        "Check whether a producer changed its format."]),
    _r("app_exception", "Unhandled application error", "Application", 0.4,
       [r"\b(?:\w+\.)*\w+(?:Exception|Error)\b"],
       "Code threw an error that was not handled.",
       ["Read the stack trace to find the failing line."]),
]


def load_rules(path: str | Path) -> list[Rule]:
    """Load extra rules from JSON: a list of objects with id, title, patterns and optional fields."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("rules", [])
    rules = []
    for item in data:
        rules.append(Rule(
            id=str(item["id"]), title=item.get("title", item["id"]),
            category=item.get("category", "Custom"),
            patterns=list(item["patterns"]) if isinstance(item["patterns"], list) else [item["patterns"]],
            rootness=float(item.get("rootness", 0.7)),
            explanation=item.get("explanation", ""), fixes=list(item.get("fixes", [])), custom=True,
        ))
    return rules
