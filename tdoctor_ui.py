"""Tunnel Doctor in Telegram: approve/reject the doctor's proposed fix and chat with it about an incident.

The doctor sends its alerts through the owner webhook with buttons `td:<verb>:<ref>` (webhook.py only lets
that namespace through). Taps and replies to those messages are forwarded to the doctor's control API, which
runs inside its collector (the process that holds the SSH keys) and answers with text + optional buttons.
Env: CLOUDBOT_TDOCTOR_URL (default http://127.0.0.1:8791), CLOUDBOT_TDOCTOR_TOKEN_FILE
(default /opt/cloudbot/data/tdoctor.token). Without the token file the buttons answer "not configured".
"""
import html
import logging
import os
import re
from pathlib import Path

import aiohttp
from aiogram import F
from aiogram.types import ForceReply, InlineKeyboardButton, InlineKeyboardMarkup

log = logging.getLogger("cloudbot.tdoctor")

URL = os.environ.get("CLOUDBOT_TDOCTOR_URL", "http://127.0.0.1:8791")
TOKEN_FILE = Path(os.environ.get("CLOUDBOT_TDOCTOR_TOKEN_FILE", "/opt/cloudbot/data/tdoctor.token"))
REF = re.compile(r"td:[a-z]{1,8}:([A-Za-z0-9_.-]{1,48})")
REF_TEXT = re.compile(r"ref ([A-Za-z0-9_.-]{1,48})\s*$")
MAX_TEXT = 4000


def ref_of(message):
    """The incident ref a doctor message belongs to: from its buttons, else from its trailing 'ref …' line."""
    if message is None:
        return None
    for row in (message.reply_markup.inline_keyboard if message.reply_markup else []):
        for b in row:
            m = REF.fullmatch(b.callback_data or "")
            if m:
                return m.group(1)
    m = REF_TEXT.search(message.text or message.caption or "")
    return m.group(1) if m else None


def markup(rows):
    if not rows:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=b["text"][:40], callback_data=b["data"]) for b in row
         if REF.fullmatch(b.get("data", ""))] for row in rows[:3]])


async def call(path, body):
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"text": "Tunnel Doctor control is not configured on this bot."}
    try:
        timeout = aiohttp.ClientTimeout(total=300)  # approve verifies against CMonitor; chat may run checks
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(URL + path, json=body, headers={"Authorization": "Bearer " + token}) as r:
                data = await r.json(content_type=None)
                if r.status != 200:
                    return {"text": f"Doctor: {data.get('error') or r.status}"}
                return data
    except Exception as e:
        log.warning("tdoctor %s failed: %s", path, e)
        return {"text": f"Doctor is not reachable ({type(e).__name__})."}


def register_tdoctor_ui(dp, host):
    owner_id = host["OWNER"]

    async def show(msg, res, ref):
        text = html.escape(str(res.get("text") or "(no answer)"))[:MAX_TEXT]
        ref = res.get("ref") or ref
        await msg.answer(text + f"\n\n<i>ref {html.escape(ref)}</i>", reply_markup=markup(res.get("buttons")))

    @dp.callback_query(F.data.startswith("td:"))
    async def td_button(cb):
        if cb.from_user.id != owner_id:
            return await cb.answer()
        m = REF.fullmatch(cb.data)
        verb, ref = cb.data.split(":")[1], m.group(1) if m else ""
        if not m:
            return await cb.answer("bad button")
        if verb == "ask":
            await cb.answer()
            return await cb.message.answer(
                f"💬 Write your question or comment (reply to this message).\n\n<i>ref {html.escape(ref)}</i>",
                reply_markup=ForceReply(input_field_placeholder="e.g. why not restart the edge?"))
        if verb not in ("ok", "no"):
            return await cb.answer("unknown action")
        await cb.answer("approved, running…" if verb == "ok" else "rejected")
        try:  # one tap only: drop the buttons so the same fix cannot be approved twice
            await cb.message.edit_reply_markup(reply_markup=markup([[{"text": "💬 Ask / comment", "data": f"td:ask:{ref}"}]]))
        except Exception:
            pass
        if verb == "ok":
            await cb.message.answer("⏳ Running the approved action and checking CMonitor…")
        res = await call("/approve" if verb == "ok" else "/reject", {"ref": ref})
        await show(cb.message, res, ref)

    def is_doctor_reply(msg):
        return (msg.from_user is not None and msg.from_user.id == owner_id and msg.reply_to_message is not None
                and msg.reply_to_message.from_user is not None and msg.reply_to_message.from_user.is_bot
                and ref_of(msg.reply_to_message) is not None)

    @dp.message(F.text, is_doctor_reply)
    async def td_reply(msg):
        ref = ref_of(msg.reply_to_message)
        await msg.bot.send_chat_action(msg.chat.id, "typing")
        res = await call("/chat", {"ref": ref, "text": msg.text[:2000]})
        await show(msg, res, ref)
