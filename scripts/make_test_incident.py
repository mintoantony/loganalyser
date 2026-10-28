"""Write a second test incident, different from the built-in demo, with a known answer.

    python scripts/make_test_incident.py [out_dir]     (default: test-incidents/2026-10-28-media)

The story (the answer is also written to ANSWER.md next to the logs, not inside them):
at 14:02 UTC media-service v2.8.0 is deployed with DEBUG logging switched on for the
thumbnail code. Its log lives on /var/data, the same volume that Redis and the upload
worker use. The volume fills from 63% to 100% by 14:31. Redis can no longer save, so it
refuses writes (MISCONF); the API cannot queue uploads or store logins, and nginx returns
500s. The worker cannot write its temp files. The loudest errors (MISCONF, 500s) are
symptoms. Background noise that is also in the healthy run: a certificate that expires
soon, a slow geocoding provider and an SMTP relay that asks for retries.

Formats: nginx access log, pino JSON, Python logging with tracebacks, Redis server log,
syslog (no year), logback, and an older rotated .gz file.
"""

from __future__ import annotations

import gzip
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
HOST = "media-01"
ANSWER = """# Test incident 2026-10-28: the answer

Point the analyser (or Claude) at the `incident` folder only, and use `baseline` as the healthy run.
Don't show it this file.

**Root cause:** media-service v2.8.0, deployed at 14:02:11 UTC, switched the log level of
`com.acme.media.thumbnails` to DEBUG (from `config/media.yaml`). It logs every thumbnail cache
lookup to `/var/data/logs/media-service.log`. `/var/data` is shared with Redis and the upload worker,
and it went from 63% to 100% full by 14:31.

**How it unfolded:**
1. 14:02 deploy with DEBUG logging; the log grows quickly.
2. 14:12 onwards, disk-monitor warns (85%, then 90% and 95%).
3. 14:31 the volume is full: media-service cannot write thumbnails, and Redis cannot save its
   snapshot or append-only file ("No space left on device").
4. Redis then refuses writes with MISCONF. The API cannot queue upload jobs or save login sessions.
5. nginx returns 500 for POST /api/uploads and POST /api/sessions. The worker fails with
   `OSError: [Errno 28] No space left on device`.

**Not the cause (also in the healthy run):** the certificate for cdn-origin.partner.example
expiring in 9 days, geocoding timeouts, SMTP 421 retries, and 404s for /favicon.ico and /wp-login.php.

**What to do:** set the thumbnail log level back to INFO (or roll back to 2.7.3), delete or
compress the debug log to free space, and check that Redis saves again (`BGSAVE`; MISCONF clears
after a successful save). Later: give Redis its own volume, cap log size with rotation, and alert
on disk use well before 100%.

**A request to follow:** `req-7c1e9a40d2` (an upload that failed in the API because Redis refused it, and in nginx as a 500).
"""


def iso(dt: datetime, sep: str = ",") -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f"{sep}{dt.microsecond // 1000:03d}"


def clf(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def redis_time(dt: datetime) -> str:
    return dt.strftime("%d %b %Y %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def syslog_time(dt: datetime) -> str:
    return dt.strftime("%b ") + f"{dt.day:>2}" + dt.strftime(" %H:%M:%S")


class Run:
    def __init__(self, day: datetime, seed: int, incident: bool):
        self.rng = random.Random(seed)
        self.start = day.replace(hour=13, minute=30)
        self.end = day.replace(hour=15, minute=0)
        self.deploy = day.replace(hour=14, minute=2, second=11, microsecond=512000)
        self.full = day.replace(hour=14, minute=31, second=4, microsecond=880000)
        self.incident = incident
        self.files: dict[str, list[tuple[datetime, str]]] = {}

    def add(self, name: str, dt: datetime, text: str) -> None:
        self.files.setdefault(name, []).append((dt, text))

    def rid(self) -> str:
        return "req-" + "".join(self.rng.choice("0123456789abcdef") for _ in range(10))

    def disk_full(self, t: datetime) -> bool:
        return self.incident and t >= self.full

    def usage(self, t: datetime) -> int:
        if not self.incident or t < self.deploy:
            return 61 + int((t - self.start).total_seconds() // 1800)
        share = (t - self.deploy) / (self.full - self.deploy)
        return min(100, int(63 + 37 * share))

    # ------------------------------------------------------------------ writers
    def media(self, dt, level, thread, logger, msg, trace=None):
        line = f"{iso(dt)} {level:<5} [{thread}] {logger} - {msg}"
        self.add("media", dt, line + ("\n" + trace if trace else ""))

    def api(self, dt, level, msg, **fields):
        obj = {"level": level, "time": int(dt.timestamp() * 1000), "pid": 41, "hostname": "api-6d9f",
               "name": "upload-api", **fields, "msg": msg}
        self.add("api", dt, json.dumps(obj))

    def worker(self, dt, level, logger, msg, trace=None):
        line = f"{iso(dt)} {level} {logger}: {msg}"
        self.add("worker", dt, line + ("\n" + trace if trace else ""))

    def redis(self, dt, mark, msg):
        self.add("redis", dt, f"1:{mark} {redis_time(dt)} {msg}")

    def syslog(self, dt, proc, msg):
        self.add("syslog", dt, f"{syslog_time(dt)} {HOST} {proc}: {msg}")

    def nginx(self, dt, method, path, status, size, rt, rid, agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
        client = f"81.{self.rng.randint(2, 250)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
        self.add("nginx", dt, f'{client} - - [{clf(dt)}] "{method} {path} HTTP/1.1" {status} {size} '
                              f'"-" "{agent}" rt={rt:.3f} request_id={rid}')

    # ------------------------------------------------------------------ the story
    def build(self) -> None:
        rng = self.rng
        version = "2.8.0" if self.incident else "2.7.3"
        if self.incident:
            self.media(self.deploy - timedelta(seconds=6), "INFO", "Thread-7", "com.acme.media.Application",
                       "Received SIGTERM, shutting down media-service v2.7.3")
            self.media(self.deploy, "INFO", "main", "com.acme.media.Application",
                       f"Starting media-service v{version} (build 4417) on {HOST}")
            self.media(self.deploy + timedelta(milliseconds=380), "INFO", "main", "com.acme.media.config.LoggingConfig",
                       "Log level for com.acme.media.thumbnails set to DEBUG (from config/media.yaml)")
            self.media(self.deploy + timedelta(milliseconds=410), "INFO", "main", "com.acme.media.config.LoggingConfig",
                       "Logging to /var/data/logs/media-service.log")
            self.media(self.deploy + timedelta(seconds=3), "INFO", "main", "com.acme.media.Application",
                       f"Started media-service v{version} in 3.1 seconds")
        else:
            self.media(self.start + timedelta(seconds=2), "INFO", "main", "com.acme.media.Application",
                       f"media-service v{version} running on {HOST}")

        t = self.start
        while t < self.end:
            t += timedelta(milliseconds=rng.randint(250, 900))
            full = self.disk_full(t)
            r = rng.random()
            if r < 0.30:                                   # image upload
                self.upload(t, self.rid(), full)
            elif r < 0.45:                                 # login
                rid = self.rid()
                self.api(t, 30, "POST /api/sessions", reqId=rid, user=f"user{rng.randint(100, 999)}")
                if full:
                    self.api(t + timedelta(milliseconds=4), 50, "Failed to store session", reqId=rid,
                             err={"type": "ReplyError", "message": "MISCONF Redis is configured to save RDB snapshots, "
                                  "but it's currently unable to persist to disk. Commands that may modify the data set are disabled."})
                    self.nginx(t + timedelta(milliseconds=8), "POST", "/api/sessions", 500, 64, 0.009, rid)
                else:
                    self.nginx(t + timedelta(milliseconds=31), "POST", "/api/sessions", 201, 312, 0.031, rid)
            elif r < 0.80:                                 # browsing
                rid = self.rid()
                path = rng.choice(["/api/images/{}", "/api/albums/{}", "/api/images/{}/thumb?size=800x600", "/health"])
                path = path.format(rng.randint(10000, 99999))
                self.nginx(t, "GET", path, 200, rng.randint(400, 90000), rng.uniform(0.004, 0.09), rid)
                if "thumb" in path and not full:
                    self.media(t + timedelta(milliseconds=2), "INFO", f"thumb-worker-{rng.randint(1, 8)}",
                               "com.acme.media.thumbnails.ThumbnailService",
                               f"Rendered thumbnail {path.split('/')[3]} 800x600 in {rng.randint(18, 140)}ms")
                if self.incident and t >= self.deploy and "thumb" in path and not full:
                    for _ in range(rng.randint(8, 14)):    # the flood
                        key = f"img/{rng.randint(10000, 99999)}/{rng.choice(['800x600', '320x240', '1600x1200'])}.webp"
                        self.media(t + timedelta(microseconds=rng.randint(10, 9000)), "DEBUG", f"thumb-worker-{rng.randint(1, 8)}",
                                   "com.acme.media.thumbnails.ThumbnailCache",
                                   f"cache lookup key={key} hit={rng.random() < 0.3} bytes={rng.randint(20000, 2500000)} "
                                   f"source=s3://acme-media/originals/{rng.randint(10000, 99999)}.jpg")
                if "thumb" in path and full and rng.random() < 0.5:
                    self.media(t + timedelta(milliseconds=3), "ERROR", f"thumb-worker-{rng.randint(1, 8)}",
                               "com.acme.media.thumbnails.ThumbnailWriter",
                               f"Failed to write thumbnail /var/data/cache/thumbs/{rng.randint(10000, 99999)}.webp",
                               "java.io.IOException: No space left on device\n"
                               "\tat java.base/sun.nio.ch.FileDispatcherImpl.write0(Native Method)\n"
                               "\tat java.base/sun.nio.ch.FileChannelImpl.write(FileChannelImpl.java:285)\n"
                               "\tat com.acme.media.thumbnails.ThumbnailWriter.store(ThumbnailWriter.java:74)\n"
                               "\tat com.acme.media.thumbnails.ThumbnailService.render(ThumbnailService.java:131)")
            elif r < 0.84:                                 # noise in both runs
                rid = self.rid()
                self.api(t, 40, "Geocoding provider timed out after 5000ms, using cached location", reqId=rid,
                         provider="geo.partner.example")
            elif r < 0.86:
                self.worker(t, "WARNING", "worker.notify",
                            f"SMTP relay answered 421 4.7.0 Try again later, retrying in 30s (job_id=mail-{rng.randint(1000, 9999)})")
            elif r < 0.88:
                self.nginx(t, "GET", rng.choice(["/favicon.ico", "/wp-login.php", "/.env"]), 404, 153, 0.001, self.rid(),
                           agent="Mozilla/5.0 (compatible; Bot/2.1)")
            else:
                self.nginx(t, "GET", "/health", 200, 2, 0.001, self.rid(), agent="kube-probe/1.30")

        if self.incident:                                  # the request named in ANSWER.md
            self.upload(self.full + timedelta(seconds=95), "req-7c1e9a40d2", True)
        self.background()

    def upload(self, t: datetime, rid: str, full: bool) -> None:
        rng = self.rng
        size = rng.randint(200_000, 9_000_000)
        self.api(t, 30, "POST /api/uploads", reqId=rid, bytes=size)
        if full:
            self.api(t + timedelta(milliseconds=6), 50, "Failed to enqueue thumbnail job", reqId=rid, queue="thumbnails",
                     err={"type": "ReplyError", "message": "MISCONF Redis is configured to save RDB snapshots, "
                          "but it's currently unable to persist to disk. Commands that may modify the data set are disabled.",
                          "stack": "ReplyError: MISCONF Redis is configured to save RDB snapshots\n"
                                   "    at parseError (/app/node_modules/redis-parser/lib/parser.js:179:12)\n"
                                   "    at JobQueue.add (/app/src/queue.js:58:21)\n"
                                   "    at uploadHandler (/app/src/routes/uploads.js:44:9)"})
            self.nginx(t + timedelta(milliseconds=12), "POST", "/api/uploads", 500, 71, 0.014, rid)
            return
        self.api(t + timedelta(milliseconds=40), 30, "Thumbnail job queued", reqId=rid, queue="thumbnails")
        self.nginx(t + timedelta(milliseconds=45), "POST", "/api/uploads", 202, 96, 0.045, rid)
        done = t + timedelta(milliseconds=rng.randint(300, 1800) + rng.choice([0, 0, 0, rng.randint(5000, 90000)]))  # some wait in the queue
        if self.disk_full(done):
            self.worker(done, "ERROR", "worker.tasks", f"Task resize_image failed request_id={rid}",
                        "Traceback (most recent call last):\n"
                        '  File "/app/worker/tasks.py", line 88, in resize_image\n'
                        "    with open(tmp_path, \"wb\") as out:\n"
                        f"OSError: [Errno 28] No space left on device: '/var/data/tmp/{rid}.jpg'")
        else:
            self.worker(done, "INFO", "worker.tasks", f"Task resize_image succeeded in {rng.uniform(0.2, 1.6):.2f}s request_id={rid}")

    def background(self) -> None:
        rng = self.rng
        t = self.start
        while t < self.end:                                # every minute
            use = self.usage(t)
            if use >= 100:
                self.syslog(t, "disk-monitor[812]", "/var/data usage 100% - volume is full")
            elif use >= 85:
                self.syslog(t, "disk-monitor[812]", f"/var/data usage {use}% (warning above 85%)")
            else:
                self.syslog(t, "disk-monitor[812]", f"/var/data usage {use}%")
            if t.minute % 5 == 0:
                self.redis(t + timedelta(seconds=1), "M", "* 100 changes in 300 seconds. Saving...")
                if self.disk_full(t):
                    self.redis(t + timedelta(seconds=1, milliseconds=40), "M", "# Write error saving DB on disk: No space left on device")
                    self.redis(t + timedelta(seconds=1, milliseconds=60), "M", "# Background saving error")
                else:
                    self.redis(t + timedelta(seconds=1, milliseconds=5), "M", f"* Background saving started by pid {rng.randint(2000, 9000)}")
                    self.redis(t + timedelta(seconds=1, milliseconds=900), "M", "* Background saving terminated with success")
            if t.minute % 15 == 0:
                self.media(t + timedelta(seconds=7), "WARN", "cert-check", "com.acme.media.tls.CertificateMonitor",
                           "Certificate for cdn-origin.partner.example expires in 9 days (2026-11-06)")
            if t.minute % 10 == 3:
                self.syslog(t + timedelta(seconds=12), "CRON[" + str(rng.randint(10000, 30000)) + "]",
                            "(root) CMD (/usr/local/bin/backup-metadata.sh)")
            t += timedelta(minutes=1)
        if self.incident:
            self.redis(self.full + timedelta(milliseconds=2), "M",
                       "# Error writing to the AOF file: No space left on device")
            self.redis(self.full + timedelta(seconds=1), "M",
                       "# Asynchronous AOF fsync is taking too long (disk is busy?). Writing the AOF buffer without waiting for fsync to complete.")
            self.syslog(self.full + timedelta(milliseconds=600), "kernel",
                        "[88231.552107] EXT4-fs warning (device nvme1n1p1): ext4_da_write_begin: No space left on device")


def write(out: Path, run: Run) -> None:
    targets = {"nginx": "nginx/access.log", "api": "upload-api/api.log", "worker": "worker/worker.log",
               "redis": "redis/redis-server.log", "syslog": "host/syslog", "media": "media-service/media-service.log"}
    for key, rel in targets.items():
        lines = sorted(run.files.get(key, []), key=lambda item: item[0])
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if key == "media":                                 # older part rotated into a .gz file
            cut = run.start + timedelta(minutes=25)
            old = [text for dt, text in lines if dt < cut]
            lines = [(dt, text) for dt, text in lines if dt >= cut]
            with gzip.open(path.with_name("media-service.log.1.gz"), "wt", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(old) + "\n")
        path.write_text("\n".join(text for _, text in lines) + "\n", encoding="utf-8", newline="\n")


def generate(out: Path, seed: int = 31) -> None:
    for name, day, run_seed, incident in [("incident", datetime(2026, 10, 28, tzinfo=UTC), seed, True),
                                          ("baseline", datetime(2026, 10, 27, tzinfo=UTC), seed + 1, False)]:
        run = Run(day, run_seed, incident)
        run.build()
        write(out / name, run)
    (out / "ANSWER.md").write_text(ANSWER, encoding="utf-8")


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("test-incidents/2026-10-28-media")
    generate(out)
    for path in sorted(out.rglob("*")):
        if path.is_file():
            print(f"{path}  ({path.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
