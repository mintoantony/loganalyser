"""Write a realistic set of demo logs: one incident run and one healthy baseline run.

The story: at 09:27 a nightly export job starts in orders-service and holds
most of the database connections. The pool runs dry, order requests time
out, PostgreSQL turns clients away, inventory-service's circuit breaker
opens, and the gateway returns 503/504s. Throughout both runs there is
background noise (a flaky e-mail relay, a slow payment provider) that should
not be mistaken for the cause.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

_PATHS_GET = ["/api/orders/{order}", "/api/inventory/{sku}", "/api/products/{sku}", "/api/health"]
_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "okhttp/4.12.0", "shop-ios/7.4.1", "curl/8.9.1"]
_SKUS = [f"SKU-{n}" for n in range(1100, 1260)]


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S,") + f"{dt.microsecond // 1000:03d}"


def _clf(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _pg(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d} UTC"


def _json_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_HIKARI_TRACE = """java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms.
\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:197)
\tat com.zaxxer.hikari.HikariDataSource.getConnection(HikariDataSource.java:100)
\tat org.springframework.jdbc.datasource.DataSourceUtils.fetchConnection(DataSourceUtils.java:160)
\tat com.shop.orders.repository.OrderRepository.save(OrderRepository.java:88)
\tat com.shop.orders.service.OrderService.placeOrder(OrderService.java:142)
\t... 48 common frames omitted"""

_REQUEST_FAILED_TRACE = """org.springframework.dao.DataAccessResourceFailureException: Unable to acquire JDBC Connection
\tat org.springframework.orm.jpa.vendor.HibernateJpaDialect.convertHibernateAccessException(HibernateJpaDialect.java:275)
\tat com.shop.orders.service.OrderService.placeOrder(OrderService.java:142)
\tat com.shop.orders.web.OrderController.create(OrderController.java:61)
Caused by: org.hibernate.exception.JDBCConnectionException: Unable to acquire JDBC Connection
\tat org.hibernate.exception.internal.SQLStateConversionDelegate.convert(SQLStateConversionDelegate.java:112)
\t... 61 more
Caused by: java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms.
\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
\t... 74 more"""


def _incident_intensity(t: datetime, start: datetime, peak: datetime, end: datetime) -> float:
    """Share of order requests that fail at time t (0 outside the incident)."""
    if t < start or t > end:
        return 0.0
    if t <= peak:
        return 0.25 + 0.65 * (t - start) / (peak - start)
    return 0.9 * (1 - (t - peak) / (end - peak)) + 0.05


def generate(out_dir: str | Path, seed: int = 7) -> dict[str, list[Path]]:
    out = Path(out_dir)
    incident = _write_run(out / "incident", datetime(2026, 10, 27, 9, 0, tzinfo=timezone.utc), seed, True)
    baseline = _write_run(out / "baseline", datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc), seed + 1, False)
    return {"incident": incident, "baseline": baseline}


def _write_run(folder: Path, base: datetime, seed: int, with_incident: bool) -> list[Path]:
    rng = random.Random(seed)
    folder.mkdir(parents=True, exist_ok=True)
    duration = timedelta(minutes=50)
    end = base + duration

    job_start = base + timedelta(minutes=27, seconds=41)
    pool_dry = base + timedelta(minutes=28, seconds=12)
    fail_start = base + timedelta(minutes=30, seconds=5)
    peak = base + timedelta(minutes=34)
    job_end = base + timedelta(minutes=41, seconds=1)
    fail_end = base + timedelta(minutes=42, seconds=30)

    gateway: list[tuple[datetime, str]] = []
    orders: list[tuple[datetime, str]] = []
    inventory: list[tuple[datetime, str]] = []
    postgres: list[tuple[datetime, str]] = []
    order_seq = 10_000

    def orders_log(dt, level, thread, logger, msg, trace=None):
        line = f"{_iso(dt)} {level:<5} [{thread}] {logger} - {msg}"
        if trace:
            line += "\n" + trace
        orders.append((dt, line))

    def inventory_log(dt, level, msg, **fields):
        obj = {"time": _json_time(dt), "level": level, "service": "inventory-service", "msg": msg}
        obj.update(fields)
        inventory.append((dt, json.dumps(obj)))

    def pg_log(dt, pid, level, msg):
        postgres.append((dt, f"{_pg(dt)} [{pid}] {level}:  {msg}"))

    # Startup lines.
    orders_log(base, "INFO", "main", "com.shop.orders.OrdersApplication", "Started OrdersApplication in 6.412 seconds (process running for 7.1)")
    orders_log(base, "INFO", "main", "com.zaxxer.hikari.HikariDataSource", "HikariPool-1 - Start completed. maximumPoolSize=20")
    inventory_log(base, "info", "Server listening on port 8081")
    pg_log(base, 1, "LOG", "database system is ready to accept connections")

    t = base + timedelta(seconds=rng.uniform(0.1, 0.6))
    while t < end:
        rid = _hex(rng, 16)
        fail_share = _incident_intensity(t, fail_start, peak, fail_end) if with_incident else 0.0
        roll = rng.random()
        thread = f"http-nio-8080-exec-{rng.randint(1, 40)}"
        client = f"10.20.{rng.randint(0, 9)}.{rng.randint(2, 250)}"
        agent = rng.choice(_AGENTS)

        if roll < 0.38:
            # Place an order: gateway -> orders -> inventory.
            order_seq += 1
            order = f"ord-{order_seq}"
            sku = rng.choice(_SKUS)
            if rng.random() < fail_share:
                wait = 30.0 + rng.uniform(0.0, 0.2)
                done = t + timedelta(seconds=wait)
                orders_log(t, "INFO", thread, "com.shop.orders.web.OrderController",
                           f"POST /api/orders received traceId={rid} orderId={order}")
                if rng.random() < 0.55:
                    orders_log(done, "ERROR", thread, "com.zaxxer.hikari.pool.HikariPool",
                               "HikariPool-1 - Connection is not available, request timed out after 30000ms.",
                               _HIKARI_TRACE)
                orders_log(done, "ERROR", thread, "com.shop.orders.web.ErrorHandler",
                           f"Request processing failed traceId={rid} orderId={order}: Unable to acquire JDBC Connection",
                           _REQUEST_FAILED_TRACE)
                status = 504 if rng.random() < 0.3 else 503
                rt = 60.0 if status == 504 else wait
                gateway.append((done, f'{client} - - [{_clf(done)}] "POST /api/orders HTTP/1.1" {status} 167 '
                                      f'"-" "{agent}" rt={rt:.3f} request_id={rid}'))
            else:
                latency = rng.uniform(0.04, 0.18) + (rng.uniform(0.5, 2.5) if fail_share else 0)
                done = t + timedelta(seconds=latency)
                orders_log(t, "INFO", thread, "com.shop.orders.web.OrderController",
                           f"POST /api/orders received traceId={rid} orderId={order}")
                inventory_log(t + timedelta(seconds=latency * 0.4), "info", "Reserved stock",
                              sku=sku, qty=rng.randint(1, 4), traceId=rid, orderId=order)
                orders_log(done, "INFO", thread, "com.shop.orders.service.OrderService",
                           f"Order {order} created in {int(latency * 1000)}ms traceId={rid}")
                if rng.random() < 0.06:
                    orders_log(done, "WARN", thread, "com.shop.orders.payment.PaymentClient",
                               f"Slow response from payment-provider: {rng.randint(2100, 4800)}ms traceId={rid}")
                gateway.append((done, f'{client} - - [{_clf(done)}] "POST /api/orders HTTP/1.1" 201 412 '
                                      f'"-" "{agent}" rt={latency:.3f} request_id={rid}'))
        else:
            path = rng.choice(_PATHS_GET)
            sku = rng.choice(_SKUS)
            path = path.format(order=f"ord-{rng.randint(9000, order_seq)}", sku=sku)
            status = 200
            latency = rng.uniform(0.003, 0.06)
            if path.startswith("/api/orders") and rng.random() < fail_share:
                status, latency = 503, 30.0 + rng.uniform(0, 0.2)
            elif rng.random() < 0.01:
                status = 404
            done = t + timedelta(seconds=latency)
            gateway.append((done, f'{client} - - [{_clf(done)}] "GET {path} HTTP/1.1" {status} '
                                  f'{rng.randint(90, 3000)} "-" "{agent}" rt={latency:.3f} request_id={rid}'))
        t += timedelta(seconds=rng.expovariate(2.2))

    # Background noise in both runs: a flaky e-mail relay and routine housekeeping.
    t = base + timedelta(minutes=3, seconds=rng.randint(0, 50))
    while t < end:
        orders_log(t, "ERROR", "notify-worker-1", "com.shop.orders.notify.EmailNotifier",
                   f"Failed to send order confirmation to customer{rng.randint(100, 999)}@example.com: "
                   f"Connection timed out (smtp-relay.internal:587)")
        t += timedelta(minutes=rng.uniform(4.5, 7.5))
    t = base + timedelta(minutes=5)
    while t < end:
        pg_log(t, 67, "LOG", "checkpoint starting: time")
        pg_log(t + timedelta(seconds=rng.uniform(20, 40)), 67, "LOG",
               f"checkpoint complete: wrote {rng.randint(800, 4200)} buffers ({rng.uniform(1, 9):.1f}%); "
               f"write={rng.uniform(20, 60):.3f} s, sync={rng.uniform(0.01, 0.3):.3f} s")
        t += timedelta(minutes=5)
    t = base + timedelta(seconds=30)
    while t < end:
        inventory_log(t, "debug", "Stock cache refreshed", entries=rng.randint(15800, 16100),
                      tookMs=rng.randint(30, 90))
        t += timedelta(seconds=60)

    if with_incident:
        export_log = "com.shop.orders.export.NightlyExportJob"
        orders_log(job_start, "INFO", "scheduling-1", export_log,
                   "Job nightly-export started (batchSize=50000, parallelism=16, source=orders,order_items)")
        batch_t = job_start + timedelta(seconds=35)
        batch = 1
        while batch_t < job_end:
            orders_log(batch_t, "INFO", f"export-worker-{rng.randint(1, 16)}", export_log,
                       f"Exported batch {batch}/26 ({batch * 50000} rows)")
            pg_log(batch_t - timedelta(seconds=0.4), 3100 + batch, "LOG",
                   f"duration: {rng.uniform(21000, 52000):.3f} ms  statement: SELECT o.*, i.* FROM orders o "
                   f"JOIN order_items i ON i.order_id = o.id WHERE o.created_at < $1 ORDER BY o.id LIMIT 50000 OFFSET {batch * 50000}")
            batch += 1
            batch_t += timedelta(seconds=rng.uniform(22, 32))
        orders_log(job_end, "INFO", "scheduling-1", export_log, "Job nightly-export completed in 13m 20s (1284331 rows)")

        t = pool_dry
        waiting = 2
        while t < fail_end:
            waiting = max(1, min(48, waiting + rng.randint(-2, 6) if t < peak else waiting - rng.randint(0, 5)))
            orders_log(t, "WARN", "HikariPool-1 housekeeper", "com.zaxxer.hikari.pool.HikariPool",
                       f"HikariPool-1 - Connection pool near capacity (total=20, active=20, idle=0, waiting={waiting})")
            t += timedelta(seconds=rng.uniform(25, 35))

        t = fail_start + timedelta(seconds=35)
        while t < fail_end - timedelta(minutes=1):
            pid = rng.randint(4000, 4999)
            if rng.random() < 0.6:
                pg_log(t, pid, "FATAL", "remaining connection slots are reserved for non-replication superuser connections")
            else:
                pg_log(t, pid, "FATAL", "sorry, too many clients already")
            t += timedelta(seconds=rng.uniform(4, 18))

        t = fail_start + timedelta(seconds=50)
        breaker_open = base + timedelta(minutes=33, seconds=12)
        breaker_closed = base + timedelta(minutes=42, seconds=50)
        inventory_log(breaker_open, "warn", "CircuitBreaker 'orders-service' changed state from CLOSED to OPEN",
                      failureRate=71.4)
        inventory_log(breaker_closed, "info", "CircuitBreaker 'orders-service' changed state from HALF_OPEN to CLOSED")
        while t < fail_end:
            order = f"ord-{rng.randint(9000, order_seq)}"
            if breaker_open <= t < breaker_closed:
                inventory_log(t, "error", "Reconcile skipped: CallNotPermittedException: CircuitBreaker 'orders-service' is OPEN",
                              orderId=order)
            else:
                inventory_log(t, "error", f"GET http://orders-service:8080/api/orders/{order}/status failed: 503 Service Unavailable",
                              orderId=order, attempt=rng.randint(1, 3),
                              error={"name": "UpstreamError", "status": 503, "message": "503 Service Unavailable"})
            t += timedelta(seconds=rng.uniform(3, 9))

    paths = []
    for name, entries in (("gateway-access.log", gateway), ("orders-service.log", orders),
                          ("inventory-service.jsonl", inventory), ("postgres.log", postgres)):
        entries.sort(key=lambda e: e[0])
        path = folder / name
        path.write_text("\n".join(line for _, line in entries) + "\n", encoding="utf-8")
        paths.append(path)
    return paths
