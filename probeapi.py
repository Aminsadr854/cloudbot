"""
The endpoint the phones talk to.

Phones reach this through the Iran relay, never directly: a handset in Iran
talking to a German address is the shape of traffic that gets throttled, and
routing it through the relay that already serves the status page keeps it
ordinary. nginx there terminates TLS and forwards here.

What it exposes is deliberately tiny. A phone asks which addresses to test and
posts back what it measured; it can read nothing else and change nothing. The
token is shared, so it is treated as an identifier rather than a secret: the
worst a leaked one allows is submitting made-up measurements, which is why a
report only ever adds a device's own opinion and never overwrites the relay's.
"""
import json
import logging
import time

from aiohttp import web

from store import Store

log = logging.getLogger("probeapi")
st = Store()

MAX_RESULTS = 60          # a report larger than this is not a phone
MAX_BODY = 64 * 1024


def _auth(request) -> bool:
    tok = request.headers.get("X-Probe-Token") or request.query.get("token", "")
    return bool(tok) and tok == st.probe_token()


async def candidates(request):
    """The addresses the phones should measure: the last scan's shortlist."""
    if not _auth(request):
        return web.json_response({"error": "unauthorised"}, status=401)
    eng_param = request.query.get("engine")
    engine_id = int(eng_param) if eng_param and eng_param.isdigit() else None
    c = st.scan_candidates(engine_id=engine_id)
    # Asking for work is itself proof of life; there is no separate heartbeat to
    # get out of step with reality.
    dev = request.query.get("device", "")
    if dev:
        st.touch_device(dev[:64], request.query.get("operator", "")[:48],
                        request.query.get("net", "")[:16],
                        request.query.get("app", "")[:16])
    # The reference addresses travel with the candidates and look no different
    # to the phone, which measures them the same way. Keeping the distinction
    # here rather than in the app means it can change without reinstalling
    # anything on a handset.
    ips = list(c.get("ips", []))
    for ip in c.get("controls", []):
        if ip not in ips:
            ips.append(ip)
    eng_cfg = st.cfscan(engine_id=c.get("engine_id") or 1)
    return web.json_response({
        "ts": c.get("ts", 0),
        "engine_id": c.get("engine_id", 1),
        "ips": ips,
        # The phones take their schedule from here, so it can be changed from
        # Telegram and applied without reinstalling anything.
        "interval_hours": st.probe_interval(),
        # Told rather than hardcoded, so the test can be changed from the server
        # without shipping a new app to phones that may never be updated.
        "port": 443,
        "rounds": 4,
        "timeout_ms": 4000,
        # The name the handshake asks for. It used to be hardcoded to a
        # Cloudflare speedtest host, which is not what a customer's connection
        # looks like at all - and an operator that filters on the name would
        # then condemn every address for a reason that has nothing to do with
        # the address. The customer's own domain is the honest thing to measure.
        # What a customer's client really asks for. For a CDN config this is a
        # different domain from the address, so the address is the wrong thing
        # to hand a phone - it would measure a handshake nobody makes.
        "sni": (st.get("probe_sni") or eng_cfg.get("fqdn")
                or "speed.cloudflare.com"),
        # Tried only where the first name failed, to tell "this address is
        # blocked" apart from "this name is blocked".
        "sni_alt": "speed.cloudflare.com",
    })


async def report(request):
    if not _auth(request):
        return web.json_response({"error": "unauthorised"}, status=401)
    if request.content_length and request.content_length > MAX_BODY:
        return web.json_response({"error": "too large"}, status=413)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad json"}, status=400)

    device = str(body.get("device") or "")[:64]
    operator = str(body.get("operator") or "unknown")[:48]
    # Which network the round was actually measured over. Older builds do not
    # send it; their reports are still accepted, they simply cannot be checked.
    net = str(body.get("net") or "")[:16]
    # Which build measured this. Two builds probe differently, so a result
    # without its version cannot be interpreted with any confidence.
    app = str(body.get("app") or "")[:16]
    results = body.get("results")
    if not device or not isinstance(results, list):
        return web.json_response({"error": "device and results required"}, status=400)

    clean = []
    for r in results[:MAX_RESULTS]:
        if not isinstance(r, dict):
            continue
        ip = str(r.get("ip") or "")[:45]
        if not ip:
            continue
        entry = {
            "ip": ip,
            "ok": bool(r.get("ok")),
            "rtt_ms": _num(r.get("rtt_ms")),
            "loss": _num(r.get("loss")),
        }
        # How far a failed attempt got: "tcp" never reached the port, "tls"
        # reached it and had the negotiation cut. Older builds send neither.
        stage = str(r.get("stage") or "")[:8]
        # "sni" means the address answered, but only under the alternate name -
        # so what is filtered is the name, not the address.
        if stage in ("ok", "tls", "tcp", "sni"):
            entry["stage"] = stage
        clean.append(entry)
    st.save_device_report(device, operator, clean, net, app)
    st.touch_device(device, operator, net, app)
    log.info("report from %s (%s/%s app=%s): %d results",
             device, operator, net or "?", app or "?", len(clean))
    return web.json_response({"ok": True, "accepted": len(clean)})


def _num(v):
    try:
        f = float(v)
        return None if f != f else round(f, 1)      # drop NaN
    except (TypeError, ValueError):
        return None


async def ping(request):
    """
    A few bytes that mean "this handset is switched on and has a network".

    Measuring is expensive and happens twice a day; knowing whether a phone is
    alive has to be far cheaper than that or it defeats the point of the
    schedule. This carries no data and does no work beyond a timestamp.
    """
    if not _auth(request):
        return web.json_response({"error": "unauthorised"}, status=401)
    dev = request.query.get("device", "")[:64]
    if dev:
        st.touch_device(dev, request.query.get("operator", "")[:48],
                        request.query.get("net", "")[:16],
                        request.query.get("app", "")[:16])
    # The two six-hour clocks - the server's window and the handset's own timer
    # - never lined up, so a phone could spend every cycle measuring the list
    # that was about to be replaced, and its verdict was never used at all. The
    # window now asks for the round rather than hoping the phone's timer lands
    # in the right place: a phone that has not reported since this shortlist was
    # published is told to measure it now.
    # Whether the phone has measured *this* list, judged by what it actually
    # reported rather than by when it reported. A round takes a quarter of an
    # hour: a phone that started before a new list was published finishes after
    # it, so its timestamp looks current while its measurements are of the list
    # before. Comparing the addresses is the only reading that is not fooled.
    eng_param = request.query.get("engine")
    engine_id = int(eng_param) if eng_param and eng_param.isdigit() else None
    cand = st.scan_candidates(engine_id=engine_id)
    current = set(cand.get("ips") or [])
    rep = st.device_reports().get(dev) or {}
    measured = {x.get("ip") for x in (rep.get("results") or [])}
    # A round run before the handshake name changed measured something else,
    # however recent it looks and however well its addresses match.
    sni_ts = int(st.get("probe_sni_ts") or 0)
    stale_test = sni_ts and (rep.get("ts") or 0) < sni_ts
    # A list published after the phone's last round must be measured again,
    # even where it shares addresses with that round: only rounds taken on
    # the current list count towards moving the domain.
    listed_ts = int(cand.get("ts") or 0)
    old_round = bool(listed_ts) and (rep.get("ts") or 0) < listed_ts
    run_now = bool(current) and (stale_test or old_round or not (measured & current))
    return web.json_response({
        "ok": True,
        "interval_hours": st.probe_interval(),
        "run_now": run_now,
    })


async def health(request):
    return web.json_response({"ok": True, "ts": int(time.time())})


def build_app():
    app = web.Application(client_max_size=MAX_BODY)
    app.router.add_get("/probe/candidates", candidates)
    app.router.add_post("/probe/report", report)
    app.router.add_get("/probe/ping", ping)
    app.router.add_get("/probe/health", health)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("probe api listening on 127.0.0.1:9600")
    web.run_app(build_app(), host="127.0.0.1", port=9600, print=None)
