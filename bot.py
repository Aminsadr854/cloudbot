"""
Cloud-account bot: manage Linode / Vultr accounts over their APIs (each through
its own proxy), create and delete servers, and turn a server into a Pasarguard
node in one press.

Everything is owner-only. The provider tokens and proxies are the crown jewels
here - they control real infrastructure and real money - so a stray user id
gets nothing, and the token entry message is deleted from the chat the moment
it is read, the same way the server-monitor bot handles passwords.
"""
import asyncio
import html
import json
import logging
import os
import secrets
import string

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (CallbackQuery, InlineKeyboardButton, Message)
from aiogram.utils.keyboard import InlineKeyboardBuilder

import secrets as _secrets

import time

import cfscanner
import providers
import replacer
import subscription
import tunnelwatch
import tunnel as tun
import watchdog
from cloudflare import CFError, Cloudflare
from provision import Panel, provision_node
from store import Store
from scanner_engine import ScannerEngine, delivery_coordinator

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cloudbot")

TOKEN = os.environ["CLOUDBOT_TOKEN"]
OWNER = int(os.environ["CLOUDBOT_OWNER"])
# Phones are given this address, never the bot host: a handset in Iran
# dialling a foreign address is the traffic that gets shaped.
# Control IP probe base URL. In production, this must be supplied via the
# CLOUDBOT_PROBE (or CLOUDBOT_PROBE_BASE) environment variable.
PROBE_BASE = os.environ.get("CLOUDBOT_PROBE_BASE",
                            "https://status.example.com")
PANEL_URL = os.environ["CLOUDBOT_PANEL_URL"]
PANEL_USER = os.environ["CLOUDBOT_PANEL_USER"]
PANEL_PASS = os.environ["CLOUDBOT_PANEL_PASS"]
SNI_CORE_ID = int(os.environ.get("CLOUDBOT_CORE_ID", "6"))

st = Store()
engines = {
    1: ScannerEngine(1, st, delivery_coordinator),
    2: ScannerEngine(2, st, delivery_coordinator),
    3: ScannerEngine(3, st, delivery_coordinator),
}
panel = Panel(PANEL_URL, PANEL_USER, PANEL_PASS)
bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())

PROVIDER_LABEL = {"linode": "🟢 Linode", "vultr": "🔵 Vultr", "hetzner": "🔴 Hetzner"}


def _own_addresses() -> set[str]:
    """
    Every IPv4 address this machine answers on.

    One of the Hetzner servers in the account is the machine this bot runs on.
    Resetting its root password reboots it, which kills the bot in the middle of
    the action and takes the new password down with it - so the confirm screen
    has to be able to say so before the tap, not after.

    Read straight from the kernel rather than shelled out, so the check costs
    nothing and cannot fail because a tool is missing.
    """
    found: set[str] = set()
    candidate = ""
    try:
        with open("/proc/net/fib_trie", "r") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("|--"):
                    candidate = stripped[3:].strip()
                elif "/32 host LOCAL" in stripped and candidate:
                    if not candidate.startswith("127."):
                        found.add(candidate)
    except Exception:
        pass
    return found


def gen_password(n=20):
    alpha = string.ascii_letters + string.digits
    # Two upper + two digit + one symbol guarantees provider complexity rules,
    # which otherwise reject an all-lowercase random string.
    base = "".join(secrets.choice(alpha) for _ in range(n))
    return "Aa1!" + base


@dp.message(F.from_user.id != OWNER)
async def deny(msg: Message):
    log.warning("rejected %s", msg.from_user.id)
    await msg.answer("این ربات خصوصی است.")


# --------------------------------------------------------------------------
# menus
# --------------------------------------------------------------------------
def kb_main():
    b = InlineKeyboardBuilder()
    b.button(text="🖥 اکانت‌ها", callback_data="accounts")
    b.button(text="➕ افزودن اکانت", callback_data="add_acc")
    b.button(text="🌐 DNS کلادفلر", callback_data="dns")
    b.button(text="🔗 تانل", callback_data="tun")
    b.button(text="🔌 نود کردن سرور", callback_data="nodeit")
    b.button(text="🔎 اسکنر آی‌پی تمیز", callback_data="scan")
    b.button(text="🩺 دیده‌بان کانفیگ", callback_data="wd")
    b.adjust(1)
    return b.as_markup()


def kb_accounts():
    b = InlineKeyboardBuilder()
    for a in st.accounts():
        prx = "🔒" if a["proxy"] else "🔓"
        b.button(text=f"{PROVIDER_LABEL.get(a['provider'], a['provider'])} · "
                      f"{a['label']} {prx}", callback_data=f"acc:{a['id']}")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1)
    return b.as_markup()


def kb_account(acc):
    b = InlineKeyboardBuilder()
    b.button(text="📋 سرورها", callback_data=f"srvs:{acc['id']}")
    b.button(text="➕ ساخت سرور", callback_data=f"new:{acc['id']}")
    b.button(text="🌐 پروکسی", callback_data=f"prx:{acc['id']}")
    b.button(text="🔑 حذف اکانت", callback_data=f"delacc:{acc['id']}")
    b.button(text="🔙 اکانت‌ها", callback_data="accounts")
    b.adjust(2, 2, 1)
    return b.as_markup()


@dp.message(CommandStart())
async def start(msg: Message, state: FSMContext):
    await state.clear()
    await msg.answer(
        "☁️ <b>مدیریت اکانت‌های ابری</b>\n\n"
        "اکانت‌های Linode و Vultr را با API و پروکسی مدیریت کن: "
        "سرورها را ببین، بساز، پاک کن، و با یک دکمه نودِ پنل کن.",
        reply_markup=kb_main())


@dp.callback_query(F.data == "home")
async def cb_home(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text("☁️ <b>مدیریت اکانت‌های ابری</b>", reply_markup=kb_main())
    await cb.answer()


@dp.callback_query(F.data == "accounts")
async def cb_accounts(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    accs = st.accounts()
    text = f"🖥 <b>اکانت‌ها</b> ({len(accs)})" if accs else "هنوز اکانتی اضافه نکردی."
    await cb.message.edit_text(text, reply_markup=kb_accounts())
    await cb.answer()


@dp.callback_query(F.data.startswith("acc:"))
async def cb_account(cb: CallbackQuery):
    acc = st.account(int(cb.data.split(":")[1]))
    if not acc:
        await cb.answer("یافت نشد", show_alert=True)
        return
    prx = acc["proxy"].split(":")[0] + ":…" if acc["proxy"] else "بدون پروکسی"
    await cb.message.edit_text(
        f"{PROVIDER_LABEL.get(acc['provider'])} <b>{html.escape(acc['label'])}</b>\n"
        f"🌐 پروکسی: <code>{html.escape(prx)}</code>",
        reply_markup=kb_account(acc))
    await cb.answer()


# --------------------------------------------------------------------------
# add account
# --------------------------------------------------------------------------
class Add(StatesGroup):
    provider = State()
    label = State()
    token = State()
    proxy = State()


@dp.callback_query(F.data == "add_acc")
async def add_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Add.provider)
    b = InlineKeyboardBuilder()
    b.button(text="🟢 Linode", callback_data="prov:linode")
    b.button(text="🔵 Vultr", callback_data="prov:vultr")
    b.button(text="🔴 Hetzner", callback_data="prov:hetzner")
    b.adjust(2)
    await cb.message.edit_text("ارائه‌دهنده را انتخاب کن:", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(Add.provider, F.data.startswith("prov:"))
async def add_provider(cb: CallbackQuery, state: FSMContext):
    await state.update_data(provider=cb.data.split(":")[1])
    await state.set_state(Add.label)
    await cb.message.edit_text("یک <b>نام</b> برای این اکانت بفرست (مثلاً <code>linode-uk</code>):")
    await cb.answer()


@dp.message(Add.label)
async def add_label(msg: Message, state: FSMContext):
    await state.update_data(label=msg.text.strip())
    await state.set_state(Add.token)
    await msg.answer("حالا <b>API Token</b> را بفرست.\n<i>پیام پس از خواندن پاک می‌شود.</i>")


@dp.message(Add.token)
async def add_token(msg: Message, state: FSMContext):
    token = msg.text.strip()
    try:
        await msg.delete()
    except Exception:
        pass
    await state.update_data(token=token)
    await state.set_state(Add.proxy)
    b = InlineKeyboardBuilder()
    b.button(text="بدون پروکسی", callback_data="noproxy")
    await msg.answer(
        "پروکسی این اکانت را بفرست به شکل\n<code>host:port:username:password</code>\n"
        "یا اگر لازم نیست، دکمهٔ زیر را بزن.", reply_markup=b.as_markup())


async def _finish_add(data, proxy, answer):
    try:
        acc = {"provider": data["provider"], "token": data["token"], "proxy": proxy}
        who = await providers.Provider(acc).whoami()
    except Exception as e:
        log.exception("add-account validation failed (provider=%s proxy=%s)",
                      data.get("provider"), bool(proxy))
        await answer(f"❌ اتصال ناموفق بود:\n<code>{html.escape(str(e)[:350])}</code>\n\n"
                     "اگر پروکسی از نوع SOCKS است، جلوش <code>socks5://</code> بگذار. "
                     "وگرنه توکن را بررسی کن.")
        return
    st.add_account(data["label"], data["provider"], data["token"], proxy)
    await answer(f"✅ اکانت <b>{html.escape(data['label'])}</b> اضافه شد.\n"
                 f"شناسایی شد: <code>{html.escape(str(who))}</code>")


@dp.message(Add.proxy)
async def add_proxy(msg: Message, state: FSMContext):
    proxy = msg.text.strip()
    try:
        providers.proxy_url(proxy)
    except ValueError:
        await msg.answer("❌ قالب پروکسی نادرست است. host:port:username:password")
        return
    data = await state.get_data()
    await state.clear()
    note = await msg.answer("در حال تست اتصال…")
    await _finish_add(data, proxy, note.edit_text)
    await msg.answer("منو:", reply_markup=kb_main())


@dp.callback_query(Add.proxy, F.data == "noproxy")
async def add_noproxy(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    await state.clear()
    await cb.message.edit_text("در حال تست اتصال…")
    await _finish_add(data, None, cb.message.edit_text)
    await cb.message.answer("منو:", reply_markup=kb_main())
    await cb.answer()


# --------------------------------------------------------------------------
# proxy change
# --------------------------------------------------------------------------
class Proxy(StatesGroup):
    value = State()


@dp.callback_query(F.data.startswith("prx:"))
async def prx_start(cb: CallbackQuery, state: FSMContext):
    acc_id = int(cb.data.split(":")[1])
    await state.set_state(Proxy.value)
    await state.update_data(acc_id=acc_id)
    b = InlineKeyboardBuilder()
    b.button(text="حذف پروکسی", callback_data="prx_clear")
    b.button(text="🔙 انصراف", callback_data=f"acc:{acc_id}")
    b.adjust(1)
    await cb.message.edit_text(
        "پروکسی جدید را بفرست (<code>host:port:username:password</code>)،\n"
        "یا حذفش کن.", reply_markup=b.as_markup())
    await cb.answer()


@dp.message(Proxy.value)
async def prx_set(msg: Message, state: FSMContext):
    proxy = msg.text.strip()
    try:
        providers.proxy_url(proxy)
    except ValueError:
        await msg.answer("❌ قالب نادرست. host:port:username:password")
        return
    data = await state.get_data()
    await state.clear()
    st.set_proxy(data["acc_id"], proxy)
    await msg.answer("✅ پروکسی به‌روز شد.", reply_markup=kb_account(st.account(data["acc_id"])))


@dp.callback_query(Proxy.value, F.data == "prx_clear")
async def prx_clear(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    await state.clear()
    st.set_proxy(data["acc_id"], None)
    await cb.message.edit_text("✅ پروکسی حذف شد.",
                               reply_markup=kb_account(st.account(data["acc_id"])))
    await cb.answer()


# --------------------------------------------------------------------------
# delete account
# --------------------------------------------------------------------------
@dp.callback_query(F.data.startswith("delacc:"))
async def del_acc(cb: CallbackQuery):
    acc_id = int(cb.data.split(":")[1])
    b = InlineKeyboardBuilder()
    b.button(text="✅ بله، حذف کن", callback_data=f"delacc_ok:{acc_id}")
    b.button(text="🔙 نه", callback_data=f"acc:{acc_id}")
    b.adjust(1)
    await cb.message.edit_text("این فقط اکانت را از ربات حذف می‌کند (سرورها دست‌نخورده). مطمئنی؟",
                               reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("delacc_ok:"))
async def del_acc_ok(cb: CallbackQuery):
    st.delete_account(int(cb.data.split(":")[1]))
    await cb.message.edit_text("✅ اکانت حذف شد.", reply_markup=kb_accounts())
    await cb.answer()


# --------------------------------------------------------------------------
# list servers
# --------------------------------------------------------------------------
@dp.callback_query(F.data.startswith("srvs:"))
async def cb_servers(cb: CallbackQuery):
    acc_id = int(cb.data.split(":")[1])
    acc = st.account(acc_id)
    await cb.message.edit_text("در حال گرفتن سرورها…")
    try:
        servers = await providers.Provider(acc).list_servers()
    except Exception as e:
        await cb.message.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:250])}</code>",
                                   reply_markup=kb_account(acc))
        await cb.answer()
        return
    b = InlineKeyboardBuilder()
    for s in servers:
        b.button(text=f"{s['label']} · {s['ip']} · {s['status']}",
                 callback_data=f"srv:{acc_id}:{s['id']}")
    b.button(text="🔙 بازگشت", callback_data=f"acc:{acc_id}")
    b.adjust(1)
    head = f"📋 <b>{len(servers)} سرور</b>" if servers else "سروری در این اکانت نیست."
    await cb.message.edit_text(head, reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("srv:"))
async def cb_server(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    try:
        s = await providers.Provider(acc).server(srv_id)
    except Exception as e:
        await cb.answer(str(e)[:180], show_alert=True)
        return
    # The provider hands the root password over once, at creation, and never
    # again - so what the bot saved then is the only copy there is. Showing it
    # here rather than only in the creation message is the difference between
    # a record you can come back to and one you had to copy in the moment.
    pw = st.server_pass(int(acc_id), srv_id)
    ip = s.get("ip")

    b = InlineKeyboardBuilder()
    b.button(text="🔌 نود کردن در پنل", callback_data=f"node:{acc_id}:{srv_id}")
    if pw and ip:
        b.button(text="📋 خط اتصال SSH", callback_data=f"srvssh:{acc_id}:{srv_id}")
    if not pw:
        b.button(text="🔑 ثبت رمز این سرور", callback_data=f"srvpw:{acc_id}:{srv_id}")
    if acc.get("provider") == "hetzner":
        b.button(text="🔄 ریست رمز روت", callback_data=f"srvrst:{acc_id}:{srv_id}")
    b.button(text="🗑 حذف سرور", callback_data=f"delsrv:{acc_id}:{srv_id}")
    b.button(text="🔙 سرورها", callback_data=f"srvs:{acc_id}")
    b.adjust(1)

    creds = (f"👤 کاربر: <code>root</code>\n"
             f"🔑 رمز: <code>{html.escape(pw)}</code>" if pw else
             "🔑 رمز: <i>ذخیره نشده — این سرور را ربات نساخته، یا رمزش عوض شده</i>")

    await cb.message.edit_text(
        f"🖥 <b>{html.escape(str(s['label']))}</b>\n"
        f"🌍 منطقه: <code>{s.get('region')}</code>\n"
        f"🔢 پلن: <code>{s.get('plan')}</code>\n"
        f"📡 آی‌پی: <code>{ip}</code>\n"
        f"وضعیت: <b>{s.get('status')}</b>\n\n"
        f"{creds}", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("srvssh:"))
async def cb_server_ssh(cb: CallbackQuery):
    """One tappable line that carries everything needed to get in."""
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    try:
        s = await providers.Provider(acc).server(srv_id)
    except Exception as e:
        await cb.answer(str(e)[:180], show_alert=True)
        return
    pw = st.server_pass(int(acc_id), srv_id)
    b = InlineKeyboardBuilder()
    b.button(text="🔙 بازگشت", callback_data=f"srv:{acc_id}:{srv_id}")
    await cb.message.edit_text(
        f"🖥 <b>{html.escape(str(s['label']))}</b>\n\n"
        f"<code>ssh root@{s.get('ip')}</code>\n\n"
        f"🔑 <code>{html.escape(pw or '—')}</code>\n\n"
        f"<code>sshpass -p '{html.escape(pw or '')}' ssh -o StrictHostKeyChecking=no "
        f"root@{s.get('ip')}</code>\n\n"
        f"<i>روی هر خط بزنی کپی می‌شود.</i>",
        reply_markup=b.as_markup())
    await cb.answer()


class SrvPw(StatesGroup):
    value = State()


@dp.callback_query(F.data.startswith("srvpw:"))
async def cb_server_setpw(cb: CallbackQuery, state: FSMContext):
    """
    Record a password for a server the bot did not create.

    Most servers here predate the bot or were made by hand, and without this
    their entry stays half a record - an address with no way in.
    """
    _, acc_id, srv_id = cb.data.split(":")
    await state.set_state(SrvPw.value)
    await state.update_data(acc_id=acc_id, srv_id=srv_id)
    await cb.message.edit_text(
        "رمز root این سرور را بفرست تا ذخیره‌اش کنم.\n\n"
        "<i>پیامت بلافاصله پاک می‌شود.</i>")
    await cb.answer()


@dp.message(SrvPw.value)
async def on_server_pw(m: Message, state: FSMContext):
    data = await state.get_data()
    pw = (m.text or "").strip()
    try:
        await m.delete()
    except Exception:
        pass
    await state.clear()
    if not pw:
        await m.answer("چیزی نفرستادی.")
        return
    st.set_server_pass(int(data["acc_id"]), data["srv_id"], pw)
    b = InlineKeyboardBuilder()
    b.button(text="🖥 بازگشت به سرور",
             callback_data=f"srv:{data['acc_id']}:{data['srv_id']}")
    await m.answer("✅ ذخیره شد.", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("srvrst:"))
async def cb_server_resetpw(cb: CallbackQuery):
    """
    Ask before resetting: Hetzner reboots the machine to apply the new password.

    On a relay or a tunnel endpoint that is a live outage, short but real, so it
    is never done on a single tap.
    """
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    try:
        s = await providers.Provider(acc).server(srv_id)
    except Exception as e:
        await cb.answer(str(e)[:180], show_alert=True)
        return
    b = InlineKeyboardBuilder()
    b.button(text="⚠️ بله، رمز را عوض کن", callback_data=f"srvrst_ok:{acc_id}:{srv_id}")
    b.button(text="🔙 نه", callback_data=f"srv:{acc_id}:{srv_id}")
    b.adjust(1)
    await cb.message.edit_text(
        f"🔄 <b>ریست رمز روت</b>\n\n"
        f"🖥 <code>{html.escape(str(s['label']))}</code>\n"
        f"📡 <code>{s.get('ip')}</code>\n"
        + ("\n⛔️ <b>این همان سروری است که خودِ این ربات روی آن اجرا می‌شود.</b>\n"
           "با ریبوت، ربات هم قطع می‌شود و رمز جدید را نمی‌بینی؛ "
           "آن را باید از پنل هتزنر برداری.\n"
           if str(s.get("ip") or "") in _own_addresses() else "")
        + "\nهتزنر یک رمز تازه می‌سازد و برای اعمالش <b>سرور را ریبوت می‌کند</b>.\n"
        "تا بالا آمدن دوباره، سرویس این سرور قطع است.\n\n"
        "رمز جدید بلافاصله نمایش داده و ذخیره می‌شود. ادامه بدهم؟",
        reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("srvrst_ok:"))
async def cb_server_resetpw_ok(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    await cb.message.edit_text("⏳ در حال گرفتن رمز تازه از هتزنر…")
    try:
        pw = await providers.Provider(acc).reset_root_password(srv_id)
    except Exception as e:
        b = InlineKeyboardBuilder()
        b.button(text="🔙 بازگشت", callback_data=f"srv:{acc_id}:{srv_id}")
        await cb.message.edit_text(
            "❌ ریست رمز انجام نشد.\n"
            f"<code>{html.escape(str(e)[:250])}</code>\n\n"
            "<i>رمز قبلی دست‌نخورده ماند.</i>", reply_markup=b.as_markup())
        await cb.answer()
        return
    # Saved before it is shown: a password applied on the server but missing
    # from the record is the one failure that locks us out of our own machine.
    st.set_server_pass(int(acc_id), srv_id, pw)
    try:
        s = await providers.Provider(acc).server(srv_id)
        ip = s.get("ip")
    except Exception:
        ip = None
    b = InlineKeyboardBuilder()
    b.button(text="🖥 بازگشت به سرور", callback_data=f"srv:{acc_id}:{srv_id}")
    await cb.message.edit_text(
        "✅ <b>رمز روت عوض شد و ذخیره شد.</b>\n\n"
        f"👤 کاربر: <code>root</code>\n"
        f"🔑 رمز جدید: <code>{html.escape(pw)}</code>\n\n"
        + (f"<code>sshpass -p '{html.escape(pw)}' ssh -o StrictHostKeyChecking=no "
           f"root@{ip}</code>\n\n" if ip else "")
        + "<i>سرور در حال ریبوت است؛ چند لحظه تا بالا آمدنش صبر کن.</i>",
        reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("delsrv:"))
async def del_srv(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    b = InlineKeyboardBuilder()
    b.button(text="⚠️ بله، سرور را نابود کن", callback_data=f"delsrv_ok:{acc_id}:{srv_id}")
    b.button(text="🔙 نه", callback_data=f"srv:{acc_id}:{srv_id}")
    b.adjust(1)
    await cb.message.edit_text("این سرور را برای همیشه از اکانت پاک می‌کند و برگشت ندارد. مطمئنی؟",
                               reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("delsrv_ok:"))
async def del_srv_ok(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    prov = providers.Provider(acc)
    await cb.message.edit_text("در حال حذف…")
    # Learn the server's IP and name BEFORE deleting it, so the matching panel
    # node can be found and removed too - otherwise a dead node is left behind.
    ip = name = None
    try:
        s = await prov.server(srv_id)
        ip, name = s.get("ip"), s.get("label")
    except Exception:
        pass
    try:
        await prov.delete_server(srv_id)
    except Exception as e:
        await cb.message.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:200])}</code>")
        await cb.answer()
        return
    st.forget_server(int(acc_id), srv_id)

    note = "✅ سرور حذف شد."
    if ip:
        try:
            removed = await panel.delete_nodes_by_address(ip, name=name)
            if removed:
                names = ", ".join(str(n) for _, n in removed)
                note += f"\n🗑 نود از پنل هم حذف شد: <b>{html.escape(names)}</b>"
            else:
                note += "\n<i>(نودی با این آی‌پی در پنل نبود)</i>"
        except Exception as e:
            note += f"\n⚠️ حذف سرور انجام شد ولی حذف نود از پنل خطا داد: <code>{html.escape(str(e)[:150])}</code>"
    await cb.message.edit_text(
        note, reply_markup=(InlineKeyboardBuilder()
                            .button(text="🔙 سرورها", callback_data=f"srvs:{acc_id}")
                            .as_markup()))
    await cb.answer()


# --------------------------------------------------------------------------
# create server (region -> plan -> image -> label)
# --------------------------------------------------------------------------
class Create(StatesGroup):
    label = State()


def _paged_kb(items, cb_prefix, back_cb, page=0, per=8):
    b = InlineKeyboardBuilder()
    start = page * per
    for value, label in items[start:start + per]:
        b.button(text=label[:40], callback_data=f"{cb_prefix}:{value}")
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"{cb_prefix}_pg:{page-1}"))
    if start + per < len(items):
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"{cb_prefix}_pg:{page+1}"))
    b.adjust(1)
    if nav:
        b.row(*nav)
    b.row(InlineKeyboardButton(text="🔙 انصراف", callback_data=back_cb))
    return b.as_markup()


@dp.callback_query(F.data.startswith("new:"))
async def new_start(cb: CallbackQuery, state: FSMContext):
    acc_id = int(cb.data.split(":")[1])
    acc = st.account(acc_id)
    await cb.message.edit_text("در حال گرفتن مناطق…")
    try:
        regions = await providers.Provider(acc).regions()
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}",
                                   reply_markup=kb_account(acc))
        await cb.answer()
        return
    await state.update_data(acc_id=acc_id, regions=regions)
    await cb.message.edit_text("🌍 منطقه را انتخاب کن:",
                               reply_markup=_paged_kb(regions, "region", f"acc:{acc_id}"))
    await cb.answer()


@dp.callback_query(F.data.startswith("region_pg:"))
async def region_page(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    page = int(cb.data.split(":")[1])
    await cb.message.edit_reply_markup(
        reply_markup=_paged_kb(data["regions"], "region", f"acc:{data['acc_id']}", page))
    await cb.answer()


@dp.callback_query(F.data.startswith("region:"))
async def pick_region(cb: CallbackQuery, state: FSMContext):
    region = cb.data.split(":", 1)[1]
    data = await state.get_data()
    acc = st.account(data["acc_id"])
    await state.update_data(region=region)
    await cb.message.edit_text("در حال گرفتن پلن‌ها…")
    try:
        plans = await providers.Provider(acc).plans(region)
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}")
        await cb.answer()
        return
    await state.update_data(plans=plans)
    await cb.message.edit_text(f"🌍 {region}\n🔢 پلن را انتخاب کن:",
                               reply_markup=_paged_kb(plans, "plan", f"acc:{data['acc_id']}"))
    await cb.answer()


@dp.callback_query(F.data.startswith("plan_pg:"))
async def plan_page(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    page = int(cb.data.split(":")[1])
    await cb.message.edit_reply_markup(
        reply_markup=_paged_kb(data["plans"], "plan", f"acc:{data['acc_id']}", page))
    await cb.answer()


@dp.callback_query(F.data.startswith("plan:"))
async def pick_plan(cb: CallbackQuery, state: FSMContext):
    plan = cb.data.split(":", 1)[1]
    data = await state.get_data()
    acc = st.account(data["acc_id"])
    await state.update_data(plan=plan)
    await cb.message.edit_text("در حال گرفتن ایمیج‌ها…")
    try:
        images = await providers.Provider(acc).images()
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}")
        await cb.answer()
        return
    await state.update_data(images=images)
    await cb.message.edit_text("💿 سیستم‌عامل را انتخاب کن:",
                               reply_markup=_paged_kb(images, "image", f"acc:{data['acc_id']}"))
    await cb.answer()


@dp.callback_query(F.data.startswith("image_pg:"))
async def image_page(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    page = int(cb.data.split(":")[1])
    await cb.message.edit_reply_markup(
        reply_markup=_paged_kb(data["images"], "image", f"acc:{data['acc_id']}", page))
    await cb.answer()


@dp.callback_query(F.data.startswith("image:"))
async def pick_image(cb: CallbackQuery, state: FSMContext):
    image = cb.data.split(":", 1)[1]
    await state.update_data(image=image)
    await state.set_state(Create.label)
    await cb.message.edit_text("یک <b>نام</b> برای سرور بفرست (فقط حروف/عدد/خط تیره):")
    await cb.answer()


@dp.message(Create.label)
async def do_create(msg: Message, state: FSMContext):
    label = "".join(c for c in msg.text.strip() if c.isalnum() or c in "-_") or "server"
    data = await state.get_data()
    await state.clear()
    acc = st.account(data["acc_id"])
    root_pw = gen_password()
    note = await msg.answer("⏳ در حال ساخت سرور…")
    try:
        srv = await providers.Provider(acc).create_server(
            label, data["region"], data["plan"], data["image"], root_pw)
    except Exception as e:
        await note.edit_text(f"❌ ساخت ناموفق: <code>{html.escape(str(e)[:250])}</code>")
        return
    # Keep the root password so "node it" can SSH in later - Linode will not
    # hand it back through the API a second time.
    st.set_server_pass(acc["id"], srv["id"], srv["root_password"])
    ip = srv.get("ip") or "(در حال تخصیص — چند لحظه بعد در لیست سرورها می‌آید)"
    b = InlineKeyboardBuilder()
    if srv.get("ip"):
        b.button(text="🔌 نود کردن در پنل", callback_data=f"node:{acc['id']}:{srv['id']}")
    b.button(text="🔙 سرورها", callback_data=f"srvs:{acc['id']}")
    b.adjust(1)
    await note.edit_text(
        f"✅ <b>سرور ساخته شد</b>\n\n"
        f"🏷 نام: <code>{html.escape(str(srv['label']))}</code>\n"
        f"📡 آی‌پی: <code>{ip}</code>\n"
        f"🌍 منطقه: <code>{srv.get('region')}</code>\n"
        f"🔢 پلن: <code>{srv.get('plan')}</code>\n"
        f"👤 یوزر: <code>root</code>\n"
        f"🔑 رمز: <code>{html.escape(srv['root_password'])}</code>\n\n"
        f"<i>رمز را جای امنی ذخیره کن.</i>", reply_markup=b.as_markup())


# --------------------------------------------------------------------------
# node it
# --------------------------------------------------------------------------
@dp.callback_query(F.data.startswith("node:"))
async def node_it(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    acc = st.account(int(acc_id))
    await cb.answer()
    prov = providers.Provider(acc)
    try:
        s = await prov.server(srv_id)
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}")
        return
    ip = s.get("ip")
    # Prefer the password the bot stored at creation; fall back to Vultr's
    # default_password if the server object still carries it.
    pw = st.server_pass(int(acc_id), srv_id) or s.get("default_password")
    if not ip or ip in ("(provisioning)", "0.0.0.0"):
        await cb.message.edit_text("آی‌پی سرور هنوز آماده نیست. کمی بعد دوباره امتحان کن.")
        return

    status = await cb.message.edit_text("🔌 <b>نود کردن در پنل</b>\n\nشروع…")
    lines = ["🔌 <b>نود کردن در پنل</b>", ""]

    async def logline(t):
        lines.append(t)
        try:
            await status.edit_text("\n".join(lines[-14:]))
        except Exception:
            pass

    if not pw:
        await logline("⚠️ رمز root این سرور در ربات نیست. اگر Linode است رمزش موقع ساخت داده شد؛ "
                      "برای نود کردن باید رمز را بدانم. لطفاً سرور را از همین ربات بساز.")
        return
    try:
        server_ca, api_key = await provision_node(ip, pw, logline)
        await logline("افزودن نود به پنل روی هستهٔ SNI-SCAN…")
        node = await panel.add_node(
            name=str(s.get("label") or ip), address=ip,
            server_ca=server_ca, api_key=api_key, core_config_id=SNI_CORE_ID)
        await logline(f"✅ <b>نود اضافه شد</b> (id={node.get('id')}). "
                      f"چند لحظه بعد در پنل سبز می‌شود.")
    except Exception as e:
        await logline(f"❌ خطا: <code>{html.escape(str(e)[:300])}</code>")


# --------------------------------------------------------------------------
# Cloudflare DNS
# --------------------------------------------------------------------------
class CF(StatesGroup):
    token = State()
    create_sub = State()
    create_ip = State()
    change_sub = State()
    change_ip = State()


def kb_dns(has_token):
    b = InlineKeyboardBuilder()
    if has_token:
        b.button(text="➕ ساخت ساب‌دامین", callback_data="cf_new")
        b.button(text="♻️ تغییر آی‌پی ساب‌دامین", callback_data="cf_chg")
        b.button(text="🔑 تغییر توکن", callback_data="cf_settok")
    else:
        b.button(text="🔑 تنظیم توکن کلادفلر", callback_data="cf_settok")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1)
    return b.as_markup()


@dp.callback_query(F.data == "dns")
async def cb_dns(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    has = bool(st.cf_token())
    text = ("🌐 <b>DNS کلادفلر</b>\n\nیک عملیات را انتخاب کن." if has else
            "🌐 <b>DNS کلادفلر</b>\n\nاول توکن API کلادفلر را تنظیم کن "
            "(دسترسی <code>Zone:DNS:Edit</code>).")
    await cb.message.edit_text(text, reply_markup=kb_dns(has))
    await cb.answer()


@dp.callback_query(F.data == "cf_settok")
async def cf_settok(cb: CallbackQuery, state: FSMContext):
    await state.set_state(CF.token)
    await cb.message.edit_text(
        "توکن API کلادفلر را بفرست.\n<i>پیام پس از خواندن پاک می‌شود.</i>")
    await cb.answer()


@dp.message(CF.token)
async def cf_token_set(msg: Message, state: FSMContext):
    token = msg.text.strip()
    try:
        await msg.delete()
    except Exception:
        pass
    await state.clear()
    note = await msg.answer("در حال تست توکن…")
    try:
        zones = await Cloudflare(token).zones()
    except Exception as e:
        await note.edit_text(f"❌ توکن کار نکرد: <code>{html.escape(str(e)[:200])}</code>",
                             reply_markup=kb_dns(bool(st.cf_token())))
        return
    st.set_cf_token(token)
    await note.edit_text(f"✅ توکن ذخیره شد. {len(zones)} دامنه در دسترس است.",
                         reply_markup=kb_dns(True))


# -- create subdomain: pick zone -> subdomain -> ip -> proxied -----------
@dp.callback_query(F.data == "cf_new")
async def cf_new(cb: CallbackQuery, state: FSMContext):
    token = st.cf_token()
    await cb.message.edit_text("در حال گرفتن دامنه‌ها…")
    try:
        zones = await Cloudflare(token).zones()
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_dns(True))
        await cb.answer()
        return
    await state.update_data(zones=zones)
    b = InlineKeyboardBuilder()
    for i, (_zid, name) in enumerate(zones):
        b.button(text=name, callback_data=f"cfz:{i}")
    b.button(text="🔙 انصراف", callback_data="dns")
    b.adjust(1)
    await cb.message.edit_text("دامنه را انتخاب کن:", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("cfz:"))
async def cf_pick_zone(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    zid, zname = data["zones"][int(cb.data.split(":")[1])]
    await state.update_data(zone_id=zid, zone_name=zname)
    await state.set_state(CF.create_sub)
    await cb.message.edit_text(
        f"دامنه: <b>{html.escape(zname)}</b>\n\n"
        f"نام ساب‌دامین را بفرست (مثلاً <code>node1</code>).\n"
        f"برای خودِ دامنهٔ اصلی، <code>@</code> بفرست.")
    await cb.answer()


@dp.message(CF.create_sub)
async def cf_create_sub(msg: Message, state: FSMContext):
    sub = msg.text.strip().lower()
    data = await state.get_data()
    fqdn = data["zone_name"] if sub == "@" else f"{sub}.{data['zone_name']}"
    await state.update_data(fqdn=fqdn)
    await state.set_state(CF.create_ip)
    await msg.answer(f"ساب‌دامین: <code>{html.escape(fqdn)}</code>\n\n"
                     f"حالا <b>آی‌پی</b> مقصد را بفرست.")


def _valid_ip(s):
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


@dp.message(CF.create_ip)
async def cf_create_ip(msg: Message, state: FSMContext):
    ip = msg.text.strip()
    if not _valid_ip(ip):
        await msg.answer("❌ آی‌پی نامعتبر است. یک IPv4 بفرست.")
        return
    await state.update_data(ip=ip)
    b = InlineKeyboardBuilder()
    b.button(text="🟠 پروکسی روشن", callback_data="cfprox:1")
    b.button(text="⚪️ پروکسی خاموش (DNS only)", callback_data="cfprox:0")
    b.adjust(1)
    await msg.answer("پروکسی کلادفلر (ابر نارنجی) روشن باشد یا خاموش؟\n"
                     "<i>برای سرورهای VPN معمولاً خاموش.</i>", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("cfprox:"))
async def cf_create_do(cb: CallbackQuery, state: FSMContext):
    proxied = cb.data.split(":")[1] == "1"
    data = await state.get_data()
    await state.clear()
    await cb.message.edit_text("در حال ساخت رکورد…")
    try:
        cf = Cloudflare(st.cf_token())
        await cf.create_a(data["zone_id"], data["fqdn"], data["ip"], proxied=proxied)
    except CFError as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_dns(True))
        await cb.answer()
        return
    await cb.message.edit_text(
        f"✅ ساخته شد\n<code>{html.escape(data['fqdn'])}</code> → "
        f"<code>{data['ip']}</code>\nپروکسی: {'روشن 🟠' if proxied else 'خاموش ⚪️'}",
        reply_markup=kb_dns(True))
    await cb.answer()


# -- change IP: subdomain -> new ip -------------------------------------
@dp.callback_query(F.data == "cf_chg")
async def cf_chg(cb: CallbackQuery, state: FSMContext):
    await state.set_state(CF.change_sub)
    await cb.message.edit_text(
        "ساب‌دامین کامل را بفرست (مثلاً <code>node1.example.com</code>):")
    await cb.answer()


@dp.message(CF.change_sub)
async def cf_change_sub(msg: Message, state: FSMContext):
    fqdn = msg.text.strip().lower().rstrip(".")
    note = await msg.answer("در حال پیدا کردن رکورد…")
    try:
        cf = Cloudflare(st.cf_token())
        zone = await cf.zone_for(fqdn)
        if not zone:
            await note.edit_text("❌ دامنهٔ این ساب‌دامین در اکانت کلادفلر نیست.",
                                 reply_markup=kb_dns(True))
            await state.clear()
            return
        rec = await cf.find_a_record(zone[0], fqdn)
    except Exception as e:
        await note.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_dns(True))
        await state.clear()
        return
    if not rec:
        await note.edit_text(f"❌ رکورد A برای <code>{html.escape(fqdn)}</code> پیدا نشد.\n"
                             "اگر نیست، از «ساخت ساب‌دامین» بساز.", reply_markup=kb_dns(True))
        await state.clear()
        return
    await state.update_data(zone_id=zone[0], record=rec, fqdn=fqdn)
    await state.set_state(CF.change_ip)
    await note.edit_text(
        f"<code>{html.escape(fqdn)}</code>\nآی‌پی فعلی: <code>{rec['content']}</code>\n"
        f"پروکسی: {'روشن 🟠' if rec.get('proxied') else 'خاموش ⚪️'}\n\n"
        f"<b>آی‌پی جدید</b> را بفرست.")


@dp.message(CF.change_ip)
async def cf_change_ip(msg: Message, state: FSMContext):
    ip = msg.text.strip()
    if not _valid_ip(ip):
        await msg.answer("❌ آی‌پی نامعتبر است.")
        return
    data = await state.get_data()
    await state.clear()
    note = await msg.answer("در حال به‌روزرسانی…")
    try:
        cf = Cloudflare(st.cf_token())
        await cf.update_a(data["zone_id"], data["record"], ip)
    except CFError as e:
        await note.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_dns(True))
        return
    await note.edit_text(
        f"✅ به‌روز شد\n<code>{html.escape(data['fqdn'])}</code> → <code>{ip}</code>\n"
        f"<i>پروکسی بدون تغییر ماند.</i>", reply_markup=kb_dns(True))


# --------------------------------------------------------------------------
# Tunnels
# --------------------------------------------------------------------------
class Tun(StatesGroup):
    foreign = State()
    iran = State()
    ports = State()
    fwd_src = State()
    fwd_srcport = State()
    fwd_dst = State()


def _parse_ssh(text):
    """host:port:user:password  (password may contain ':')."""
    parts = text.strip().split(":", 3)
    if len(parts) != 4:
        return None
    host, port, user, pw = parts
    if not port.isdigit():
        return None
    return {"host": host, "port": int(port), "user": user, "password": pw}


def kb_tun():
    b = InlineKeyboardBuilder()
    b.button(text="➕ تانل جدید", callback_data="tun_new")
    b.button(text="📝 ثبت تانل موجود", callback_data="tun_reg")
    b.button(text="↪️ فوروارد", callback_data="tun_fwd")
    b.button(text="📋 تانل‌ها / حذف", callback_data="tun_list")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1)
    return b.as_markup()


@dp.callback_query(F.data == "tun")
async def cb_tun(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    j = st.jump()
    jl = f"واسط ایران: <code>{j['host']}</code>" if j else "⚠️ واسط ایران تنظیم نشده"
    await cb.message.edit_text(f"🔗 <b>تانل</b>\n{jl}", reply_markup=kb_tun())
    await cb.answer()


@dp.callback_query(F.data == "tun_new")
async def tun_new(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Tun.foreign)
    await cb.message.edit_text(
        "🌍 دسترسی <b>سرور خارج</b> را بفرست:\n<code>host:port:user:password</code>\n"
        "<i>پورت SSH معمولاً 22.</i>")
    await cb.answer()


@dp.message(Tun.foreign)
async def tun_foreign(msg: Message, state: FSMContext):
    s = _parse_ssh(msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    if not s:
        await msg.answer("❌ قالب نادرست. <code>host:port:user:password</code>")
        return
    await state.update_data(foreign=s)
    await state.set_state(Tun.iran)
    await msg.answer("🇮🇷 دسترسی <b>سرور ایران</b> را بفرست:\n<code>host:port:user:password</code>")


@dp.message(Tun.iran)
async def tun_iran(msg: Message, state: FSMContext):
    s = _parse_ssh(msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    if not s:
        await msg.answer("❌ قالب نادرست. <code>host:port:user:password</code>")
        return
    await state.update_data(iran=s)
    await state.set_state(Tun.ports)
    await msg.answer("🔢 پورت‌هایی که می‌خواهی تونل شوند را بفرست (با کاما):\n"
                     "مثلاً <code>9093,1194</code>")


@dp.message(Tun.ports)
async def tun_ports(msg: Message, state: FSMContext):
    ports = [p.strip() for p in msg.text.replace(" ", "").split(",") if p.strip().isdigit()]
    if not ports:
        await msg.answer("❌ پورت معتبر بفرست.")
        return
    await state.update_data(ports=ports)
    b = InlineKeyboardBuilder()
    b.button(text="GRE (UDP دارد، CPU صفر)", callback_data="tuntype:gre")
    b.button(text="paytun (فقط TCP، هرجا کار می‌کند)", callback_data="tuntype:paytun")
    b.adjust(1)
    await msg.answer("نوع تانل را انتخاب کن:", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("tuntype:"))
async def tun_build(cb: CallbackQuery, state: FSMContext):
    kind = cb.data.split(":")[1]
    data = await state.get_data()
    await state.clear()
    iran, foreign, ports = data["iran"], data["foreign"], data["ports"]
    jump = st.jump()
    status = await cb.message.edit_text(f"🔗 ساخت تانل <b>{kind}</b>…")
    lines = [f"🔗 ساخت تانل <b>{kind}</b>", ""]

    async def logline(t):
        lines.append(t)
        try:
            await status.edit_text("\n".join(lines[-14:]))
        except Exception:
            pass

    try:
        if kind == "gre":
            existing = [t for t in st.tunnels() if t["kind"] == "gre"]
            subnet_n = (max([t["detail"].get("subnet_n", 0) for t in existing], default=0) + 1) % 250 or 1
            detail = await tun.build_gre(iran, foreign, ports, jump, subnet_n, logline)
        else:
            psk = _secrets.token_urlsafe(36)
            port = 20000 + (len(st.tunnels()) % 20000)
            detail = await tun.build_paytun(iran, foreign, ports, jump, psk, port, logline)
            detail["psk"] = psk
        detail.update({"iran": iran, "foreign": foreign})
        tid = st.add_tunnel(kind, iran["host"], foreign["host"], ",".join(ports), detail)
        extra = detail.get("ping") or detail.get("check") or ""
        await logline(f"✅ تانل ساخته شد (#{tid}).\n<code>{html.escape(str(extra)[:250])}</code>")
    except Exception as e:
        log.exception("tunnel build failed")
        await logline(f"❌ خطا: <code>{html.escape(str(e)[:300])}</code>")


@dp.callback_query(F.data == "tun_list")
async def tun_list(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    ts = st.tunnels()
    if not ts:
        await cb.message.edit_text("تانلی ثبت نشده.", reply_markup=kb_tun())
        await cb.answer()
        return
    b = InlineKeyboardBuilder()
    for t in ts:
        if t["kind"] == "forward":
            label = f"↪️ #{t['id']} {t['foreign_host'] or t['iran_host']} :{t['ports']}"
        else:
            label = f"🔗 #{t['id']} {t['kind']} {t['iran_host']}↔{t['foreign_host']} :{t['ports']}"
        b.button(text=label[:48], callback_data=f"tundel:{t['id']}")
    b.button(text="🔙 بازگشت", callback_data="tun")
    b.adjust(1)
    await cb.message.edit_text("برای حذف، روی تانل بزن:", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("tundel:"))
async def tun_del(cb: CallbackQuery):
    tid = int(cb.data.split(":")[1])
    b = InlineKeyboardBuilder()
    b.button(text="✅ بله، حذف کن", callback_data=f"tundelok:{tid}")
    b.button(text="🔙 نه", callback_data="tun_list")
    b.adjust(1)
    await cb.message.edit_text("این تانل/فوروارد را از هر دو سر حذف کنم؟", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("tundelok:"))
async def tun_del_ok(cb: CallbackQuery):
    tid = int(cb.data.split(":")[1])
    t = st.tunnel(tid)
    if not t:
        await cb.answer("یافت نشد", show_alert=True)
        return
    d = t["detail"]
    jump = st.jump()
    status = await cb.message.edit_text("در حال حذف…")
    lines = ["🗑 حذف تانل", ""]

    async def logline(x):
        lines.append(x)
        try:
            await status.edit_text("\n".join(lines[-12:]))
        except Exception:
            pass

    try:
        if t["kind"] == "gre":
            await tun.teardown_gre(d["iran"], d["foreign"], d, jump, logline)
        elif t["kind"] == "paytun":
            await tun.teardown_paytun(d["iran"], d["foreign"], d, jump, logline)
        else:  # forward
            await tun.teardown_forward(d["server"], d, jump, d.get("is_iran", False), logline)
        st.delete_tunnel(tid)
        await logline("✅ حذف شد.")
    except Exception as e:
        log.exception("teardown failed")
        await logline(f"⚠️ خطا در حذف: <code>{html.escape(str(e)[:200])}</code>\n"
                      "از دیتابیس ربات حذف شد؛ اگر لازم بود دستی روی سرور پاک کن.")
        st.delete_tunnel(tid)


# -- forward ------------------------------------------------------------
@dp.callback_query(F.data == "tun_fwd")
async def tun_fwd(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Tun.fwd_src)
    await cb.message.edit_text(
        "↪️ <b>فوروارد</b>\n\nدسترسی <b>سرور مبدأ</b> را بفرست "
        "(ایران یا خارج):\n<code>host:port:user:password</code>")
    await cb.answer()


@dp.message(Tun.fwd_src)
async def fwd_src(msg: Message, state: FSMContext):
    s = _parse_ssh(msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    if not s:
        await msg.answer("❌ قالب نادرست.")
        return
    await state.update_data(fwd_src=s)
    b = InlineKeyboardBuilder()
    b.button(text="🇮🇷 سرور ایران است", callback_data="fwdloc:1")
    b.button(text="🌍 سرور خارج است", callback_data="fwdloc:0")
    b.adjust(1)
    await msg.answer("این سرور مبدأ ایران است یا خارج؟\n"
                     "<i>(برای ایران از واسط رد می‌شوم)</i>", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("fwdloc:"))
async def fwd_loc(cb: CallbackQuery, state: FSMContext):
    await state.update_data(fwd_is_iran=cb.data.split(":")[1] == "1")
    await state.set_state(Tun.fwd_srcport)
    await cb.message.edit_text("پورت <b>مبدأ</b> را بفرست (روی همین سرور شنیده می‌شود):")
    await cb.answer()


@dp.message(Tun.fwd_srcport)
async def fwd_srcport(msg: Message, state: FSMContext):
    if not msg.text.strip().isdigit():
        await msg.answer("❌ پورت عدد است.")
        return
    await state.update_data(fwd_srcport=msg.text.strip())
    await state.set_state(Tun.fwd_dst)
    await msg.answer("مقصد را بفرست به شکل <code>ip:port</code>:")


@dp.message(Tun.fwd_dst)
async def fwd_dst(msg: Message, state: FSMContext):
    raw = msg.text.strip()
    if ":" not in raw or not raw.split(":")[1].isdigit():
        await msg.answer("❌ قالب مقصد: <code>ip:port</code>")
        return
    dst_ip, dst_port = raw.rsplit(":", 1)
    data = await state.get_data()
    await state.clear()
    server = data["fwd_src"]
    is_iran = data["fwd_is_iran"]
    jump = st.jump()
    status = await msg.answer("↪️ در حال برقراری فوروارد…")
    lines = ["↪️ فوروارد", ""]

    async def logline(x):
        lines.append(x)
        try:
            await status.edit_text("\n".join(lines[-10:]))
        except Exception:
            pass

    try:
        # a placeholder id for the nft table name, then persist
        tid_guess = (max([t["id"] for t in st.tunnels()], default=0) + 1)
        detail = await tun.build_forward(server, data["fwd_srcport"], dst_ip, dst_port,
                                         jump, is_iran, tid_guess, logline)
        detail.update({"server": server, "is_iran": is_iran,
                       "dst": f"{dst_ip}:{dst_port}", "src_port": data["fwd_srcport"]})
        tid = st.add_tunnel("forward", server["host"] if is_iran else None,
                            None if is_iran else server["host"],
                            data["fwd_srcport"], detail)
        await logline(f"✅ فوروارد برقرار شد (#{tid}):\n"
                      f"<code>{server['host']}:{data['fwd_srcport']}</code> → "
                      f"<code>{dst_ip}:{dst_port}</code>")
    except Exception as e:
        log.exception("forward failed")
        await logline(f"❌ خطا: <code>{html.escape(str(e)[:300])}</code>")


# --------------------------------------------------------------------------
# Node a server directly (SSH creds given, not via a cloud account)
# --------------------------------------------------------------------------
class NodeIt(StatesGroup):
    ssh = State()


@dp.callback_query(F.data == "nodeit")
async def nodeit_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(NodeIt.ssh)
    await cb.message.edit_text(
        "🔌 <b>نود کردن سرور</b>\n\n"
        "دسترسی SSH سرور را بفرست:\n<code>host:port:user:password</code>\n"
        "<i>پورت معمولاً 22. پیام پس از خواندن پاک می‌شود.</i>")
    await cb.answer()


@dp.message(NodeIt.ssh)
async def nodeit_do(msg: Message, state: FSMContext):
    s = _parse_ssh(msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    await state.clear()
    if not s:
        await msg.answer("❌ قالب نادرست. <code>host:port:user:password</code>",
                         reply_markup=kb_main())
        return
    status = await msg.answer("🔌 <b>نود کردن سرور</b>\n\nشروع…")
    lines = ["🔌 <b>نود کردن سرور</b>", ""]

    async def logline(t):
        lines.append(t)
        try:
            await status.edit_text("\n".join(lines[-14:]))
        except Exception:
            pass

    try:
        server_ca, api_key = await provision_node(
            s["host"], s["password"], logline, user=s["user"], port=s["port"])
        await logline("افزودن نود به پنل روی هستهٔ SNI-SCAN…")
        node = await panel.add_node(name=s["host"], address=s["host"],
                                    server_ca=server_ca, api_key=api_key,
                                    core_config_id=SNI_CORE_ID)
        await logline(f"✅ <b>نود اضافه شد</b> (id={node.get('id')}). "
                      f"چند لحظه بعد در پنل سبز می‌شود.")
    except Exception as e:
        log.exception("standalone node-it failed")
        await logline(f"❌ خطا: <code>{html.escape(str(e)[:300])}</code>")
    await msg.answer("منو:", reply_markup=kb_main())


# --------------------------------------------------------------------------
# Cloudflare clean-IP scanner
# --------------------------------------------------------------------------
class Scan(StatesGroup):
    server = State()
    subdomain = State()
    interval = State()


def _fmt_metrics(d):
    def r(x, n=1):
        return round(x, n) if isinstance(x, (int, float)) else "?"
    return (f"{r(d.get('rtt'))}ms · jitter {r(d.get('jitter'), 2)}ms · "
            f"loss {round((d.get('loss') or 0)*100)}% · "
            f"{('%.0f Mbps' % d['mbps']) if d.get('mbps') else '—'}")


def kb_scan(cfg=None):
    b = InlineKeyboardBuilder()
    b.button(text="⚙️ مدیریت موتورها (۳ موتور)", callback_data="scan_engines")
    b.button(text="🖥 سرور اسکن (ایران)", callback_data="scan_srv")
    b.button(text="🌐 تنظیم دامنه‌ها", callback_data="scan_dom")
    b.button(text="⏱ زمان‌بندی", callback_data="scan_sched")
    auto1 = st.cfscan(1).get("auto_apply")
    auto2 = st.cfscan(2).get("auto_apply")
    auto3 = st.cfscan(3).get("auto_apply")
    all_auto = auto1 and auto2 and auto3
    b.button(text=("✅ اعمال خودکار: همه روشن" if all_auto else "⚪️ اعمال خودکار"),
             callback_data="scan_auto")
    b.button(text="▶️ اسکن الان", callback_data="scan_now")
    b.button(text="📊 وضعیت زنده", callback_data="scan_status")
    b.button(text="📋 آی‌پی‌های پیدا شده", callback_data="scan_found")
    b.button(text="📱 تأیید با گوشی‌ها", callback_data="scan_verified")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1, 2, 2, 2, 2, 1)
    return b.as_markup()


def _scan_summary(cfg=None):
    cfg1 = st.cfscan(1)
    cfg2 = st.cfscan(2)
    cfg3 = st.cfscan(3)
    ssh = cfg1.get("ssh") or {}
    srv = ssh.get("host", "—")
    iv = cfg1.get("interval_hours") or 6

    def _eng_desc(eid, c):
        dom = c.get("fqdn") or "تعیین نشده"
        ip = c.get("last_best_ip") or "—"
        st_info = engines[eid].get_status()
        state = st_info.get("state", "idle")
        if state == "scanning":
            icon = "🟢 در حال اسکن (Scanning)"
        elif state == "waiting_delivery":
            icon = f"⏳ در صف ارسال به گوشی‌ها ({st_info.get('eta_minutes', 0)} دقیقه)"
        elif state == "testing":
            icon = "🟢 در حال سنجش گوشی‌ها (Testing)"
        elif state == "error":
            icon = f"🔴 خطا ({st_info.get('detail','')[:20]})"
        else:
            icon = "⚪️ آماده (Idle)"
        return (f"🔹 <b>موتور {eid} (Engine {eid}):</b> {icon}\n"
                f"   🌐 دامنه: <code>{html.escape(dom)}</code> | آی‌پی: <code>{ip}</code>")

    return (
        "🔎 <b>اسکنر آی‌پی تمیز کلادفلر (۳ موتور مستقل)</b>\n\n"
        f"🖥 سرور اسکن: <code>{srv}</code>\n"
        f"⏱ زمان‌بندی: هر <b>{iv}</b> ساعت | اسکن پیوسته هر <b>{SCAN_GAP_MINUTES}</b> دقیقه\n\n"
        f"{_eng_desc(1, cfg1)}\n\n"
        f"{_eng_desc(2, cfg2)}\n\n"
        f"{_eng_desc(3, cfg3)}\n\n"
        "<i>هر ۳ موتور به صورت کاملاً مستقل و موازی اسکن می‌کنند. "
        "نتایج با فاصلهٔ ۵ دقیقه‌ای به گوشی‌ها فرستاده می‌شوند.</i>"
    )


@dp.callback_query(F.data == "scan")
async def cb_scan(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text(_scan_summary(), reply_markup=kb_scan())
    await cb.answer()


@dp.callback_query(F.data == "scan_engines")
async def cb_scan_engines(cb: CallbackQuery):
    b = InlineKeyboardBuilder()
    for eid in (1, 2, 3):
        b.button(text=f"🌐 تغییر دامنه موتور {eid}", callback_data=f"scandom:{eid}")
        b.button(text=f"▶️ اسکن موتور {eid}", callback_data=f"scannow:{eid}")
    b.button(text="🔙 بازگشت به اسکنر", callback_data="scan")
    b.adjust(2, 2, 2, 1)

    lines = ["⚙️ <b>مدیریت ۳ موتور اسکن مستقل</b>\n"]
    for eid in (1, 2, 3):
        c = st.cfscan(eid)
        dom = c.get("fqdn") or "تعیین نشده"
        ip = c.get("last_best_ip") or "—"
        st_info = engines[eid].get_status()
        state = st_info.get("state", "idle")
        state_str = {
            "scanning": "🟢 در حال اسکن",
            "waiting_delivery": f"⏳ در صف ارسال به گوشی‌ها ({st_info.get('eta_minutes', 0)} دقیقه دیگر)",
            "testing": "🟢 در حال سنجش گوشی‌ها",
            "error": f"🔴 خطا ({html.escape(st_info.get('detail',''))})",
            "idle": "⚪️ آماده"
        }.get(state, state)
        auto_s = "✅ روشن" if c.get("auto_apply") else "⚪️ خاموش"
        lines.append(
            f"🔹 <b>موتور {eid} (Engine {eid})</b>\n"
            f"• دامنهٔ متصل: <code>{html.escape(dom)}</code>\n"
            f"• وضعیت: {state_str}\n"
            f"• اعمال خودکار: {auto_s}\n"
            f"• آخرین آی‌پی منتخب: <code>{ip}</code>\n"
        )
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data == "scan_srv")
async def scan_srv(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Scan.server)
    await cb.message.edit_text(
        "دسترسی SSH سرور ایرانِ اسکن را بفرست:\n<code>host:port:user:password</code>\n"
        "<i>اسکن از این سرور انجام می‌شود (باید داخل ایران باشد). "
        "اگر از خارج SSH نمی‌دهد، از واسط تانل رد می‌شود. پیام پاک می‌شود.</i>")
    await cb.answer()


@dp.message(Scan.server)
async def scan_srv_set(msg: Message, state: FSMContext):
    s = _parse_ssh(msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    await state.clear()
    if not s:
        await msg.answer("❌ قالب نادرست. host:port:user:password", reply_markup=kb_scan())
        return
    for eid in (1, 2, 3):
        st.update_cfscan(eid, ssh=s)
    await msg.answer("✅ سرور اسکن برای همهٔ موتورها ذخیره شد.", reply_markup=kb_scan())


@dp.callback_query(F.data == "scan_dom")
async def scan_dom_select(cb: CallbackQuery):
    token = st.cf_token()
    if not token:
        await cb.answer("اول توکن کلادفلر را در بخش «DNS کلادفلر» تنظیم کن.", show_alert=True)
        return
    b = InlineKeyboardBuilder()
    for eid in (1, 2, 3):
        dom = st.cfscan(eid).get("fqdn") or "تعیین نشده"
        b.button(text=f"موتور {eid}: {dom[:28]}", callback_data=f"scandom:{eid}")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text(
        "🌐 <b>تنظیم دامنه برای هر موتور اسکن</b>\n\n"
        "هر موتور به صورت مستقل به یک دامنه در کلادفلر متصل می‌شود:\n\n"
        f"• موتور ۱: <code>{st.cfscan(1).get('fqdn') or '—'}</code>\n"
        f"• موتور ۲: <code>{st.cfscan(2).get('fqdn') or '—'}</code>\n"
        f"• موتور ۳: <code>{st.cfscan(3).get('fqdn') or '—'}</code>\n\n"
        "برای تغییر دامنهٔ هر موتور، روی دکمهٔ آن بزن:",
        reply_markup=b.as_markup()
    )
    await cb.answer()


@dp.callback_query(F.data.startswith("scandom:"))
async def scan_pick_engine_dom(cb: CallbackQuery, state: FSMContext):
    eid = int(cb.data.split(":")[1])
    token = st.cf_token()
    if not token:
        await cb.answer("اول توکن کلادفلر را در بخش «DNS کلادفلر» تنظیم کن.", show_alert=True)
        return
    await cb.message.edit_text(f"در حال گرفتن دامنه‌ها برای موتور {eid}…")
    try:
        zones = await Cloudflare(token).zones()
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_scan())
        await cb.answer()
        return
    await state.update_data(zones=zones, engine_id=eid)
    b = InlineKeyboardBuilder()
    for i, (_zid, name) in enumerate(zones):
        b.button(text=name, callback_data=f"scanz:{i}")
    b.button(text="🔙 انصراف", callback_data="scan_dom")
    b.adjust(1)
    await cb.message.edit_text(f"دامنه‌ای که آی‌پی تمیز <b>موتور {eid}</b> پشتش برود را انتخاب کن:",
                               reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("scanz:"))
async def scan_pick_zone(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    zid, zname = data["zones"][int(cb.data.split(":")[1])]
    eid = data.get("engine_id", 1)
    await state.update_data(zone_id=zid, zone_name=zname, engine_id=eid)
    await state.set_state(Scan.subdomain)
    await cb.message.edit_text(
        f"موتور: <b>موتور {eid}</b>\n"
        f"دامنه: <b>{html.escape(zname)}</b>\n\n"
        f"نام ساب‌دامین را بفرست (مثلاً <code>cf</code>). برای خودِ دامنه <code>@</code>.")
    await cb.answer()


@dp.message(Scan.subdomain)
async def scan_sub_set(msg: Message, state: FSMContext):
    sub = msg.text.strip().lower()
    data = await state.get_data()
    eid = data.get("engine_id", 1)
    await state.clear()
    fqdn = data["zone_name"] if sub == "@" else f"{sub}.{data['zone_name']}"
    cfg = st.update_cfscan(eid, zone_id=data["zone_id"], zone_name=data["zone_name"], fqdn=fqdn)
    await msg.answer(f"✅ دامنهٔ مقصد موتور {eid}: <code>{html.escape(fqdn)}</code>", reply_markup=kb_scan(cfg))


@dp.callback_query(F.data == "scan_sched")
async def scan_sched(cb: CallbackQuery, state: FSMContext):
    b = InlineKeyboardBuilder()
    for h in (1, 3, 6, 12, 24):
        b.button(text=f"هر {h} ساعت", callback_data=f"scaniv:{h}")
    b.button(text="✏️ دلخواه", callback_data="scaniv_custom")
    b.button(text="⛔️ دستی (بدون زمان‌بندی)", callback_data="scaniv:0")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(3, 2, 1, 1)
    await cb.message.edit_text("هر چند ساعت یک‌بار اسکن شود؟ (روی هر ۳ موتور اعمال می‌شود)", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("scaniv:"))
async def scan_iv_set(cb: CallbackQuery):
    h = int(cb.data.split(":")[1])
    for eid in (1, 2, 3):
        st.update_cfscan(eid, interval_hours=(h or None))
    await cb.message.edit_text(_scan_summary(), reply_markup=kb_scan())
    await cb.answer("ذخیره شد")


@dp.callback_query(F.data == "scaniv_custom")
async def scan_iv_custom(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Scan.interval)
    await cb.message.edit_text("تعداد ساعت را بفرست (عدد):")
    await cb.answer()


@dp.message(Scan.interval)
async def scan_iv_custom_set(msg: Message, state: FSMContext):
    await state.clear()
    try:
        h = int(msg.text.strip())
        assert h > 0
    except Exception:
        await msg.answer("❌ عدد معتبر بفرست.", reply_markup=kb_scan())
        return
    for eid in (1, 2, 3):
        st.update_cfscan(eid, interval_hours=h)
    await msg.answer(f"✅ هر {h} ساعت برای همهٔ موتورها.", reply_markup=kb_scan())


@dp.callback_query(F.data == "scan_auto")
async def scan_auto(cb: CallbackQuery):
    b = InlineKeyboardBuilder()
    for eid in (1, 2, 3):
        auto = st.cfscan(eid).get("auto_apply")
        icon = "✅ روشن" if auto else "⚪️ خاموش"
        dom = st.cfscan(eid).get("fqdn") or "تعیین نشده"
        b.button(text=f"موتور {eid} ({dom[:15]}): {icon}", callback_data=f"scan_auto_eng:{eid}")
    b.button(text="🔄 تغییر وضعیت همه", callback_data="scan_auto_eng:all")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text(
        "♻️ <b>اعمال خودکار آی‌پی روی دامنه‌ها</b>\n\n"
        "وقتی هر موتور آی‌پی بهتری پیدا کند، در صورت روشن بودن اعمال خودکار، "
        "دامنهٔ اختصاصی همان موتور در کلادفلر آپدیت می‌شود.",
        reply_markup=b.as_markup()
    )
    await cb.answer()


@dp.callback_query(F.data.startswith("scan_auto_eng:"))
async def scan_auto_toggle(cb: CallbackQuery):
    arg = cb.data.split(":")[1]
    if arg == "all":
        new_val = not st.cfscan(1).get("auto_apply")
        for eid in (1, 2, 3):
            st.update_cfscan(eid, auto_apply=new_val)
    else:
        eid = int(arg)
        cur = st.cfscan(eid).get("auto_apply")
        st.update_cfscan(eid, auto_apply=not cur)
    await scan_auto(cb)


@dp.callback_query(F.data == "scan_status")
async def scan_status(cb: CallbackQuery):
    lines = ["📊 <b>وضعیت زندهٔ موتورهای اسکن</b>\n"]
    for eid in (1, 2, 3):
        cfg = st.cfscan(eid)
        ts = cfg.get("last_scan_ts")
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "هرگز"
        st_info = engines[eid].get_status()
        state = st_info.get("state", "idle")
        state_str = {
            "scanning": "🟢 در حال اسکن (Scanning)",
            "waiting_delivery": f"⏳ در صف ارسال به گوشی‌ها ({st_info.get('eta_minutes', 0)} دقیقه دیگر)",
            "testing": "🟢 در حال سنجش گوشی‌ها (Testing)",
            "error": f"🔴 خطا: {html.escape(st_info.get('detail',''))}",
            "idle": "⚪️ آماده (Idle)"
        }.get(state, state)
        dom = cfg.get("fqdn") or "تعیین نشده"
        lines.append(
            f"🔹 <b>موتور {eid} (Engine {eid})</b>\n"
            f"• وضعیت: {state_str}\n"
            f"• دامنهٔ متصل: <code>{html.escape(dom)}</code>\n"
            f"• آخرین اسکن: <b>{when}</b>\n"
            f"• بهترین آی‌پی: <code>{cfg.get('last_best_ip') or '—'}</code>"
        )
        if cfg.get("last_best"):
            lines.append(f"• معیار بهترین: {_fmt_metrics(cfg['last_best'])}")
        lines.append("")
    b = InlineKeyboardBuilder()
    b.button(text="🔄 به‌روزرسانی", callback_data="scan_status")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data == "scan_found")
async def scan_found(cb: CallbackQuery):
    await show_scan_found_for_engine(cb, 1)


@dp.callback_query(F.data.startswith("scan_found_eng:"))
async def cb_scan_found_pick_eng(cb: CallbackQuery):
    eid = int(cb.data.split(":")[1])
    await show_scan_found_for_engine(cb, eid)


async def show_scan_found_for_engine(cb: CallbackQuery, eid: int):
    found = st.found_ips(eid)
    b = InlineKeyboardBuilder()
    for i in (1, 2, 3):
        prefix = "👉 " if i == eid else ""
        b.button(text=f"{prefix}موتور {i}", callback_data=f"scan_found_eng:{i}")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(3, 1)

    dom = st.cfscan(eid).get("fqdn") or "—"
    if not found:
        await cb.message.edit_text(
            f"📋 <b>آی‌پی‌های پیدا شده - موتور {eid}</b>\n"
            f"🌐 دامنه: <code>{html.escape(dom)}</code>\n\n"
            "هنوز آی‌پی‌ای برای این موتور ثبت نشده.",
            reply_markup=b.as_markup())
        await cb.answer()
        return

    lines = [f"📋 <b>آخرین آی‌پی‌های تمیز - موتور {eid}</b>",
             f"🌐 دامنه: <code>{html.escape(dom)}</code>", ""]
    for e in found[:10]:
        when = time.strftime("%m-%d %H:%M", time.localtime(e.get("ts", 0)))
        applied = " ✅اعمال شد" if e.get("applied") else ""
        lines.append(f"<code>{e.get('ip')}</code> — {_fmt_metrics(e)}{applied}  <i>{when}</i>")
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())
    await cb.answer()


async def _apply_ip(fqdn, ip):
    """Point the target subdomain at `ip` (DNS-only, so the real IP is exposed)."""
    token = st.cf_token()
    cf = Cloudflare(token)
    zone = await cf.zone_for(fqdn)
    if not zone:
        raise RuntimeError("دامنهٔ مقصد در کلادفلر نیست")
    rec = await cf.find_a_record(zone[0], fqdn)
    if rec:
        await cf.update_a(zone[0], rec, ip)
    else:
        await cf.create_a(zone[0], fqdn, ip, proxied=False)


async def _scan_pass(log):
    """
    One pass of the continuous scan. Its results go into the window's pool.

    The download stage is skipped here. It is the entire bandwidth cost of a
    scan, and paying it on every pass around the clock would be absurd when the
    only addresses whose throughput matters are the handful that reach the end
    of a window. Latency, jitter and loss - which is what decides a proxy - cost
    almost nothing to measure.
    """
    cfg = st.cfscan()
    ssh = cfg.get("ssh")
    if not ssh:
        return 0
    results, _tail = await cfscanner.run_scan(
        ssh, st.jump(), log, limit=SCAN_SAMPLE,
        final=PHONE_SHORTLIST, no_speed=True)
    st.pool_add(results)
    return len(results)


MAX_RESHORTLIST = 4       # fresh shortlists per window before giving the pool a rest


async def _reshortlist(log):
    """
    Hand the phones a different fifty, now, without waiting for the window.

    When every address on a shortlist comes back unreachable from a handset
    whose own connection was proven working, the shortlist is the problem: the
    operator is filtering exactly the addresses the relay likes best. Waiting
    six hours to try again would leave customers on that operator broken for
    six hours. The pool usually holds far more than the fifty that were handed
    out, so the next best untried batch goes out immediately and the phones are
    asked to measure it.

    Bounded, because a night when the operator blocks everything would
    otherwise burn the whole pool in minutes and learn nothing new.
    """
    cand = st.scan_candidates()
    tried = set(cand.get("tried") or []) | set(cand.get("ips") or [])
    rounds = int(cand.get("reshortlists") or 0)
    if rounds >= MAX_RESHORTLIST:
        await log("سقف لیست‌های جایگزین این پنجره پر شد")
        # Worth saying out loud once, and only once per window. Having tried
        # several hundred addresses and had every one refused on both operators
        # while the relay saw nothing wrong, the conclusion is no longer about
        # which address to pick - it is that this transport is being filtered,
        # and no address will fix it.
        if not st.get(f"blocked_alert_{cand.get('ts')}"):
            st.set(f"blocked_alert_{cand.get('ts')}", 1)
            try:
                await bot.send_message(
                    OWNER,
                    f"⛔️ <b>هیچ آدرسی روی موبایل کار نمی‌کند</b>\n\n"
                    f"{len(tried)} آدرس در {MAX_RESHORTLIST} لیست پیاپی امتحان شد. "
                    f"روی هر دو اپراتور پورت باز می‌شود و TLS قطع می‌شود، در حالی که "
                    f"اینترنت خود گوشی‌ها سالم است و سرور ایران روی همان آدرس‌ها "
                    f"پکت‌لاس صفر می‌بیند.\n\n"
                    f"<b>این با عوض کردن آی‌پی حل نمی‌شود.</b> چیزی که فیلتر می‌شود "
                    f"خودِ مسیر است، نه آدرس خاص. تانل‌های خودت مسیر دیگری دارند و "
                    f"سالم‌اند.\n\n"
                    f"<i>تا پنجرهٔ بعدی دیگر پیام نمی‌دهم.</i>")
            except Exception:
                log.exception("blocked alert failed")
        return False

    blocked = st.blocked_ips()
    pool = st.scan_pool().get("ips") or {}
    fresh = [dict(m, ip=ip) for ip, m in pool.items()
             if ip not in tried and ip not in blocked]
    if len(fresh) < 5:
        await log("آدرس نیازمودهٔ کافی در استخر نیست")
        return False
    fresh.sort(key=cfscanner.score)
    batch = fresh[:PHONE_SHORTLIST]

    st.set_scan_candidates(batch, _control_ips(), keep=PHONE_SHORTLIST)
    st.set_candidate_meta(tried=sorted(tried | {e["ip"] for e in batch}),
                          reshortlists=rounds + 1)
    await log(f"لیست جایگزین #{rounds + 1}: {len(batch)} آدرس تازه به گوشی‌ها داده شد")
    try:
        await bot.send_message(
            OWNER,
            f"🚫 <b>اپراتور کل لیست را بسته بود</b>\n\n"
            f"گوشی هیچ‌کدام از {len(cand.get('ips') or [])} آدرس را نتوانست باز کند "
            f"(پورت باز می‌شد، TLS قطع می‌شد) در حالی که اینترنت خودش سالم بود.\n\n"
            f"<i>اگر دور بعد هم همین شد، مسئله نام دامنه است نه آی‌پی.</i>\n\n"
            f"📋 {len(batch)} آدرس تازه فرستادم و از گوشی‌ها خواستم دوباره بسنجند "
            f"(تلاش {rounds + 1} از {MAX_RESHORTLIST}).")
    except Exception:
        log.exception("reshortlist alert failed")
    return True


async def _close_window(log, *, apply_if_better):
    """
    Six hours of scanning are over: pick the best, prove them, hand them on.

    The pool holds whatever the passes turned up. Its best are re-measured once
    here as a fixed list - this time with the download stage - because they were
    each seen at a different moment and a single comparable measurement is what
    a ranking needs. Then they go to the phones, and the choice is made from
    whatever the phones have to say about them.
    """
    cfg = st.cfscan()
    pool = st.scan_pool()
    blocked = st.blocked_ips()
    entries = [dict(m, ip=ip) for ip, m in (pool.get("ips") or {}).items()
               if ip not in blocked]
    if not entries:
        # Everything the window found is on the blocked list; better to hand out
        # the best of a bad set than nothing at all, and let the phones re-judge.
        entries = [dict(m, ip=ip) for ip, m in (pool.get("ips") or {}).items()]
    if not entries:
        raise RuntimeError("استخر اسکن خالی است")
    entries.sort(key=cfscanner.score)
    top = [e["ip"] for e in entries[:PHONE_SHORTLIST]]
    await log(f"پایان پنجره: {len(entries)} آدرس در {pool.get('passes')} پاس — "
              f"{len(top)} تای برتر دوباره سنجیده می‌شوند")

    ssh = cfg.get("ssh")
    results, _tail = await cfscanner.run_scan(ssh, st.jump(), log, only=top,
                                              final=PHONE_SHORTLIST)
    if not results:
        # The re-check found nothing alive; the pool's own numbers still stand.
        results = entries[:PHONE_SHORTLIST]
    results.sort(key=cfscanner.score)

    # Refreshed once a window: cheap, and it cannot go stale between windows.
    sni = await _refresh_probe_sni()
    if sni:
        await log(f"نام دست‌دادن مشتری‌ها: {sni}")

    shortlist = results[:PHONE_SHORTLIST]
    st.set_scan_candidates(shortlist, _control_ips(), keep=PHONE_SHORTLIST)
    st.set_candidate_meta(tried=[e["ip"] for e in shortlist], reshortlists=0)
    st.pool_reset()

    fqdn = cfg.get("fqdn")
    live_ip = None
    cf = rec = zone = None
    if fqdn and st.cf_token():
        try:
            cf = Cloudflare(st.cf_token())
            zone = await cf.zone_for(fqdn)
            rec = await cf.find_a_record(zone[0], fqdn) if zone else None
            live_ip = rec["content"] if rec else None
        except Exception as e:
            await log(f"⚠️ خواندن رکورد دامنه خطا داد: {html.escape(str(e)[:150])}")

    # A list published this second has been measured by no phone, and the
    # domain moves only on a round both phones completed on this list, with the
    # relay confirming the address beats the live one. So publishing never moves
    # the domain; phone_recheck does, once both reports are in.
    st.set("awaiting_phones", 0)
    keep = next((r for r in shortlist if r["ip"] == live_ip), None)
    fields = {"last_scan_ts": int(time.time())}
    if keep:
        fields.update(last_best_ip=keep["ip"], last_best=keep)
    st.update_cfscan(**fields)
    await log("لیست تازه منتشر شد؛ دامنه فقط با تأیید هر دو گوشی و برتری در تست سرور "
              f"عوض می‌شود. آدرس فعلی: {live_ip or '—'}")
    return (keep or shortlist[0]), False, False, "منتظر سنجش هر دو گوشی"


# Kept for compatibility: delegates to Engine 1
async def _do_scan(log, *, apply_if_better):
    await engines[1].scan_pass(log)
    return await engines[1].close_window(log, apply_if_better=apply_if_better)


@dp.callback_query(F.data == "scan_now")
async def scan_now_menu(cb: CallbackQuery):
    b = InlineKeyboardBuilder()
    for eid in (1, 2, 3):
        dom = st.cfscan(eid).get("fqdn") or f"موتور {eid}"
        b.button(text=f"▶️ اسکن موتور {eid} ({dom[:15]})", callback_data=f"scannow:{eid}")
    b.button(text="🚀 اسکن همزمان هر ۳ موتور", callback_data="scannow:all")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text("کدام موتور را می‌خواهی همین الان اسکن کنی؟", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("scannow:"))
async def cb_scannow_run(cb: CallbackQuery):
    arg = cb.data.split(":")[1]
    target_ids = [1, 2, 3] if arg == "all" else [int(arg)]
    cfg1 = st.cfscan(1)
    if not cfg1.get("ssh"):
        await cb.answer("اول سرور اسکن را تنظیم کن.", show_alert=True)
        return
    await cb.answer("اسکن شروع شد.")
    status_msg = await cb.message.edit_text("🔎 شروع اسکن…")

    async def run_one(eid):
        lines = [f"🔎 <b>اسکن موتور {eid}</b>", ""]
        async def logline(t):
            lines.append(t)
            try:
                await status_msg.edit_text("\n".join(lines[-12:]))
            except Exception:
                pass
        try:
            await engines[eid].scan_pass(logline)
            best, better, applied, why = await engines[eid].close_window(
                logline, apply_if_better=st.cfscan(eid).get("auto_apply"))
            return eid, best, applied, None
        except Exception as e:
            log.exception("[ENGINE %d] scan_now failed", eid)
            return eid, None, False, str(e)

    results = await asyncio.gather(*(run_one(eid) for eid in target_ids))
    out_lines = ["✅ <b>نتیجهٔ اسکن:</b>\n"]
    for eid, best, applied, err in results:
        c = st.cfscan(eid)
        dom = c.get("fqdn") or "—"
        if err:
            out_lines.append(f"❌ <b>موتور {eid}:</b> خطا: <code>{html.escape(err[:100])}</code>")
        elif best:
            app_str = " (✅ اعمال شد)" if applied else ""
            out_lines.append(
                f"🔹 <b>موتور {eid}</b> (دامنه: <code>{dom}</code>)\n"
                f"   ⭐️ بهترین: <code>{best['ip']}</code>{app_str}\n"
                f"   {_fmt_metrics(best)}\n"
            )
    b = InlineKeyboardBuilder()
    b.button(text="🔙 منوی اسکنر", callback_data="scan")
    await status_msg.edit_text("\n".join(out_lines), reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("scan_apply_last"))
async def scan_apply_last(cb: CallbackQuery):
    parts = cb.data.split(":")
    eid = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
    cfg = st.cfscan(eid)
    ip = cfg.get("last_best_ip")
    fqdn = cfg.get("fqdn")
    if not (ip and fqdn):
        await cb.answer("آی‌پی یا دامنه تنظیم نشده.", show_alert=True)
        return
    await cb.answer()
    try:
        await _apply_ip(fqdn, ip)
        await cb.message.edit_text(f"✅ موتور {eid}: <code>{fqdn}</code> → <code>{ip}</code>",
                                   reply_markup=kb_scan())
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_scan())


async def phone_recheck():
    """Run independent phone recheck loops for Engine 1, Engine 2, and Engine 3 concurrently."""
    async def _notify(text):
        try:
            await bot.send_message(OWNER, text)
        except Exception:
            log.exception("notify failed")

    tasks = [
        asyncio.create_task(engines[eid].recheck_loop(notify_fn=_notify))
        for eid in (1, 2, 3)
    ]
    await asyncio.gather(*tasks, return_exceptions=True)


async def scan_scheduler():
    """Run independent scan scheduler loops for Engine 1, Engine 2, and Engine 3 concurrently."""
    async def _notify(text):
        try:
            await bot.send_message(OWNER, text)
        except Exception:
            log.exception("notify failed")

    tasks = [
        asyncio.create_task(engines[eid].scan_loop(notify_fn=_notify))
        for eid in (1, 2, 3)
    ]
    await asyncio.gather(*tasks, return_exceptions=True)


# ==========================================================================
# endpoint watchdog: probe every config from Iran, heal the CDN ones
# ==========================================================================
class Watch(StatesGroup):
    add = State()
    sub = State()


async def _sync_from_sub(url=None):
    """
    Re-read the subscription and reconcile the watched targets against it.

    The owner changes domains from time to time, so the subscription - not this
    bot's database - is the source of truth for what exists. Targets imported
    from it are replaced wholesale on every sync; anything added by hand is
    left alone. Alert state is carried across by address, so a config that
    survives a sync does not lose its failure streak and re-alert.
    """
    url = url or st.sub_url()
    if not url:
        raise RuntimeError("لینک ساب ثبت نشده")
    configs = await subscription.load(url)

    direct = [c for c in configs if not c["cdn"] and not c.get("udp")]
    cdn = [c for c in configs if c["cdn"]]
    udp = [c for c in configs if c.get("udp")]

    old = st.watch_targets()
    manual = [t for t in old if t.get("source") != "sub"]
    old_sub = {(t["host"], t["port"]): t for t in old if t.get("source") == "sub"}

    rows = list(manual)
    next_id = max([t["id"] for t in old], default=0) + 1
    added, kept = [], []
    for c in direct:
        key = (c["host"], int(c["port"]))
        prev = old_sub.get(key)
        if prev:
            trec = next((tunnelwatch.tunnel_for_ip(st, ip)
                         for ip in (c.get("ips") or [])
                         if tunnelwatch.tunnel_for_ip(st, ip)), None)
            prev.update(label=c["label"], tls=c["tls"], sni=c.get("sni"),
                        proto=c["proto"],
                        kind="tunnel" if trec else "direct",
                        tunnel_id=trec["id"] if trec else None)
            rows.append(prev)
            kept.append(prev)
        else:
            # A config whose address resolves onto one of our Iran relays is
            # tunnelled: the box the customer dials is not the box that serves
            # them, so it has to be repaired as a tunnel, not as a server.
            trec = next((tunnelwatch.tunnel_for_ip(st, ip)
                         for ip in (c.get("ips") or [])
                         if tunnelwatch.tunnel_for_ip(st, ip)), None)
            rows.append({"id": next_id, "label": c["label"], "host": c["host"],
                         "port": int(c["port"]), "tls": c["tls"],
                         "sni": c.get("sni"), "proto": c["proto"],
                         "source": "sub", "heal": False, "fqdn": None,
                         "kind": "tunnel" if trec else "direct",
                         "tunnel_id": trec["id"] if trec else None})
            added.append(c)
            next_id += 1

    removed = [t for k, t in old_sub.items()
               if k not in {(c["host"], int(c["port"])) for c in direct}]

    st.replace_watch_targets(rows)
    # Drop alert state for targets that no longer exist.
    live = {str(t["id"]) for t in rows}
    st.set_watch_state({k: v for k, v in st.watch_state().items() if k in live})
    st.set_watch_cfg(sub_sync_ts=int(time.time()))
    return {"added": added, "removed": removed, "kept": kept,
            "cdn": cdn, "udp": udp, "total": len(rows)}


@dp.callback_query(F.data == "wd_sub")
async def wd_sub(cb: CallbackQuery, state: FSMContext):
    await cb.answer()
    await state.set_state(Watch.sub)
    have = "\n\n<i>یک لینک ساب از قبل ثبت است؛ فرستادن لینک تازه جایگزینش می‌کند.</i>" \
        if st.sub_url() else ""
    await cb.message.answer(
        "📥 <b>وارد کردن کانفیگ‌ها از لینک ساب</b>\n\n"
        "لینک ساب را بفرست. خودم کانفیگ‌ها را از تویش درمی‌آورم، کانفیگ‌های "
        "<b>مستقیم</b> را زیر نظر می‌گیرم، و <b>هر روز یک‌بار</b> دوباره از "
        "همین لینک می‌خوانم تا اگر دامنه‌ای عوض کردی خودش به‌روز شود." + have +
        "\n\nبرای انصراف /cancel")


@dp.message(Watch.sub)
async def wd_sub_save(msg: Message, state: FSMContext):
    url = msg.text.strip()
    if not url.startswith("http"):
        await msg.answer("یک لینک http/https بفرست یا /cancel")
        return
    await state.clear()
    try:
        await msg.delete()      # the link is a bearer secret
    except Exception:
        pass
    note = await msg.answer("در حال خواندن لینک ساب…")
    try:
        res = await _sync_from_sub(url)
    except Exception as e:
        await note.edit_text(f"❌ نشد: <code>{html.escape(str(e)[:250])}</code>")
        return
    st.set_sub_url(url)
    lines = [f"✅ <b>{len(res['added'])} کانفیگ مستقیم اضافه شد</b>", ""]
    for c in res["added"][:20]:
        lines.append(f"• {html.escape(str(c['label']))} — "
                     f"<code>{html.escape(c['host'])}:{c['port']}</code>"
                     f"{' TLS' if c['tls'] else ''}")
    if len(res["added"]) > 20:
        lines.append(f"… و {len(res['added']) - 20} تای دیگر")
    extra = []
    if res["cdn"]:
        extra.append(f"{len(res['cdn'])} کانفیگ پشت کلادفلر (تستشان لبهٔ "
                     f"کلادفلر را می‌سنجد نه سرور تو، جدا نگه داشتم)")
    if res["udp"]:
        extra.append(f"{len(res['udp'])} کانفیگ UDP مثل hysteria/tuic "
                     f"(با تست TCP قابل سنجش نیستند)")
    if extra:
        lines += ["", "<i>" + "؛ ".join(extra) + "</i>"]
    lines += ["", "🔁 هر ۲۴ ساعت دوباره از همین لینک می‌خوانم."]
    await note.edit_text("\n".join(lines), reply_markup=kb_watch())


def kb_watch():
    cfg = st.watch_cfg()
    n = len(st.watch_targets())
    b = InlineKeyboardBuilder()
    b.button(text=("🟢 روشن" if cfg["enabled"] else "🔴 خاموش") + " — تغییر",
             callback_data="wd_toggle")
    b.button(text=f"⏱ هر {cfg['interval_minutes']} دقیقه", callback_data="wd_iv")
    b.button(text=("🔄 جایگزینی خودکار سرور: روشن" if cfg.get("auto_replace")
                   else "⏸ جایگزینی خودکار سرور: خاموش"), callback_data="wd_repl")
    b.button(text=f"📋 کانفیگ‌ها ({n})", callback_data="wd_list")
    b.button(text="📥 از لینک ساب", callback_data="wd_sub")
    b.button(text="➕ افزودن دستی", callback_data="wd_add")
    b.button(text="▶️ بررسی الان", callback_data="wd_now")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1)
    return b.as_markup()


@dp.callback_query(F.data == "wd")
async def cb_watch(cb: CallbackQuery):
    await cb.answer()
    cfg = st.watch_cfg()
    scan = st.cfscan()
    srv = scan.get("ssh", {}).get("host") if scan.get("ssh") else None
    last = st.watch_last()
    healthy = sum(1 for r in last if r.get("verdict") == "healthy")
    summary = (f"وضعیت آخرین بررسی: {healthy} از {len(last)} سالم" if last
               else "هنوز بررسی‌ای انجام نشده.")
    body = (
        "🩺 <b>دیده‌بان کانفیگ</b>\n\n"
        "هر کانفیگ را از داخل ایران تست می‌کنم و فرق «قطع» با «فیلتر شده» را "
        "تشخیص می‌دهم (TCP وصل می‌شود ولی TLS ریست می‌خورد = فیلتر).\n"
        "برای کانفیگ‌های پشت کلادفلر، اگر خراب شود خودم آی‌پی تمیز تازه پیدا "
        "می‌کنم و پشت دامنه می‌گذارم.\n\n"
        f"سرور تست (ایران): <code>{html.escape(srv) if srv else 'تنظیم نشده — از منوی اسکنر تنظیمش کن'}</code>\n"
        f"{summary}")
    await cb.message.edit_text(body, reply_markup=kb_watch())


@dp.callback_query(F.data == "wd_toggle")
async def wd_toggle(cb: CallbackQuery):
    cfg = st.watch_cfg()
    if not cfg["enabled"]:
        if not st.cfscan().get("ssh"):
            await cb.answer("اول سرور اسکن ایران را در منوی اسکنر تنظیم کن.",
                            show_alert=True)
            return
        if not st.watch_targets():
            await cb.answer("اول حداقل یک کانفیگ اضافه کن.", show_alert=True)
            return
    cfg = st.set_watch_cfg(enabled=not cfg["enabled"])
    await cb.answer("روشن شد." if cfg["enabled"] else "خاموش شد.")
    await cb.message.edit_reply_markup(reply_markup=kb_watch())


@dp.callback_query(F.data == "wd_repl")
async def wd_repl(cb: CallbackQuery):
    cfg = st.watch_cfg()
    if not cfg.get("auto_replace"):
        # Turning this on lets the bot spend money and delete servers on its
        # own, so say plainly what it will do before it is allowed to.
        cfg = st.set_watch_cfg(auto_replace=True)
        await cb.answer()
        await cb.message.answer(
            "🔄 <b>جایگزینی خودکار سرور روشن شد</b>\n\n"
            "از این به بعد اگر کانفیگ مستقیمی خراب بماند:\n"
            "• سرور پشتش را پیدا می‌کنم\n"
            "• روی همان اکانت، همان لوکیشن و همان پلن سرور نو می‌سازم\n"
            "• نودش می‌کنم و دامنه را رویش می‌برم (کاربر چیزی نمی‌فهمد)\n"
            "• از داخل ایران تستش می‌کنم و <b>تازه بعد از سالم بودن</b> سرور "
            "قدیمی را حذف می‌کنم\n"
            "• اگر اکانت بن شده باشد، روی اکانت دیگری در همان دیتاسنتر می‌سازم\n"
            "• اگر اکانتی نمانده باشد، خبر می‌دهم\n\n"
            f"⚠️ سقف: روزی {MAX_REPLACE_PER_DAY} جایگزینی برای هر کانفیگ — "
            "تا اگر کل یک دیتاسنتر فیلتر شد، بی‌نهایت سرور ساخته نشود.")
    else:
        cfg = st.set_watch_cfg(auto_replace=False)
        await cb.answer("خاموش شد.")
    try:
        await cb.message.edit_reply_markup(reply_markup=kb_watch())
    except Exception:
        pass


@dp.callback_query(F.data == "wd_iv")
async def wd_iv(cb: CallbackQuery):
    await cb.answer()
    b = InlineKeyboardBuilder()
    for m in (5, 10, 15, 30, 60):
        b.button(text=f"{m} دقیقه", callback_data=f"wd_iv_set:{m}")
    b.adjust(3)
    await cb.message.answer("هر چند دقیقه یک‌بار بررسی شود؟", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("wd_iv_set:"))
async def wd_iv_set(cb: CallbackQuery):
    m = int(cb.data.split(":")[1])
    st.set_watch_cfg(interval_minutes=m)
    await cb.answer(f"هر {m} دقیقه.")
    await cb.message.edit_text(f"✅ بازهٔ بررسی شد هر {m} دقیقه.")


@dp.callback_query(F.data == "wd_add")
async def wd_add(cb: CallbackQuery, state: FSMContext):
    await cb.answer()
    await state.set_state(Watch.add)
    await cb.message.answer(
        "➕ <b>افزودن کانفیگ به دیده‌بان</b>\n\n"
        "آدرس کانفیگ را به این شکل بفرست:\n"
        "<code>نام | هاست | پورت | tls</code>\n\n"
        "مثال‌ها:\n"
        "<code>ترکیه وی‌لس | tr.example.com | 443 | tls</code>\n"
        "<code>اوپن‌وی‌پی‌ان | 91.108.145.140 | 1194 | notls</code>\n\n"
        "اگر هاست یک دامنهٔ پشت کلادفلر است و می‌خواهی موقع خرابی خودم آی‌پی "
        "تمیز تازه پشتش بگذارم، آخرش <code>| heal</code> اضافه کن:\n"
        "<code>سی‌دی‌ان | cdn.example.com | 443 | tls | heal</code>\n\n"
        "برای انصراف /cancel")


@dp.message(Watch.add)
async def wd_add_save(msg: Message, state: FSMContext):
    parts = [p.strip() for p in msg.text.split("|")]
    if len(parts) < 4:
        await msg.answer("فرمت درست نبود. دوباره بفرست یا /cancel")
        return
    label, host, port, tls = parts[0], parts[1], parts[2], parts[3].lower()
    if not port.isdigit():
        await msg.answer("پورت باید عدد باشد.")
        return
    heal = len(parts) > 4 and parts[4].lower() == "heal"
    await state.clear()
    tid = st.add_watch({"label": label, "host": host, "port": int(port),
                        "tls": tls in ("tls", "yes", "1", "بله"),
                        "heal": heal, "fqdn": host if heal else None})
    await msg.answer(
        f"✅ اضافه شد: <b>{html.escape(label)}</b> — "
        f"<code>{html.escape(host)}:{port}</code>"
        + ("\n♻️ خوددرمانی آی‌پی تمیز فعال است." if heal else ""),
        reply_markup=kb_watch())


@dp.callback_query(F.data == "wd_list")
async def wd_list(cb: CallbackQuery):
    await cb.answer()
    rows = st.watch_targets()
    if not rows:
        await cb.message.edit_text("هنوز کانفیگی اضافه نکردی.", reply_markup=kb_watch())
        return
    last = {str(r.get("id")): r for r in st.watch_last()}
    lines = ["📋 <b>کانفیگ‌های تحت نظر</b>", ""]
    b = InlineKeyboardBuilder()
    for t in rows:
        r = last.get(str(t["id"]))
        status = watchdog.describe(r) if r else "— هنوز بررسی نشده"
        heal = " ♻️" if t.get("heal") else ""
        lines.append(f"<b>{html.escape(t['label'])}</b>{heal}\n"
                     f"   <code>{html.escape(t['host'])}:{t['port']}</code>\n"
                     f"   {status}")
        b.button(text=f"🗑 {t['label'][:20]}", callback_data=f"wd_del:{t['id']}")
    b.button(text="🔙 بازگشت", callback_data="wd")
    b.adjust(1)
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("wd_del:"))
async def wd_del(cb: CallbackQuery):
    tid = int(cb.data.split(":")[1])
    st.delete_watch(tid)
    await cb.answer("حذف شد.")
    await wd_list(cb)


@dp.callback_query(F.data == "wd_now")
async def wd_now(cb: CallbackQuery):
    if not st.watch_targets():
        await cb.answer("اول کانفیگ اضافه کن.", show_alert=True)
        return
    if not st.cfscan().get("ssh"):
        await cb.answer("سرور تست ایران تنظیم نشده.", show_alert=True)
        return
    await cb.answer()
    note = await cb.message.edit_text("🩺 در حال بررسی کانفیگ‌ها از داخل ایران…")
    try:
        results = await _do_watch(alert=False)
    except Exception as e:
        await note.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:250])}</code>",
                             reply_markup=kb_watch())
        return
    lines = ["🩺 <b>نتیجهٔ بررسی</b>", ""]
    for r in results:
        lines.append(f"<b>{html.escape(str(r.get('label')))}</b>\n   "
                     f"{watchdog.describe(r)}")
    await note.edit_text("\n".join(lines), reply_markup=kb_watch())


# Each failed candidate is destroyed within a minute, so hunting is cheap and
# the limits can be generous; they exist to stop a runaway loop, not to ration.
IP_HUNT_ATTEMPTS = 8          # fresh IPs tried inside one repair run
MAX_REPLACE_PER_DAY = 25      # repair runs per config per day
CONFIRM_TRIES = 3             # extra probes before touching anything
CONFIRM_DELAY = 60            # seconds between them


async def _confirm_down(target, log_fn=None):
    """
    Make sure a config is really down before rebuilding anything.

    A relay hiccup, a moment of packet loss, a server that pauses under load -
    any of these can lose a probe round without the config being broken. Acting
    on the first failure would mean tearing down working servers because of a
    blip, which costs far more than the blip did. So the config is re-tested
    CONFIRM_TRIES more times, a minute apart, and only a config that fails
    every single one of them is treated as genuinely down.

    Returns True if it stayed down for all of them.
    """
    for i in range(1, CONFIRM_TRIES + 1):
        await asyncio.sleep(CONFIRM_DELAY)
        try:
            res = await watchdog.run_probes(st.cfscan()["ssh"], st.jump(), [target])
        except Exception as e:
            log.warning("confirm probe failed: %s", e)
            continue
        verdict = res[0].get("verdict") if res else "down"
        if log_fn:
            await log_fn(f"تست تأیید {i}/{CONFIRM_TRIES}: {verdict}")
        if verdict not in watchdog.BAD:
            return False
    return True


class TunReg(StatesGroup):
    iran = State()
    foreign = State()
    kind = State()
    ports = State()


@dp.callback_query(F.data == "tun_reg")
async def tun_reg(cb: CallbackQuery, state: FSMContext):
    await cb.answer()
    await state.set_state(TunReg.iran)
    await cb.message.answer(
        "📝 <b>ثبت تانل موجود</b>\n\n"
        "تانلی که خودت از قبل زده‌ای را معرفی کن تا دیده‌بان بتواند تعمیرش کند. "
        "چیزی ساخته یا خراب نمی‌شود — فقط ثبت می‌شود.\n\n"
        "۱/۴ — دسترسی <b>سرور ایران</b> (همان آی‌پی‌ای که روی کانفیگ است):\n"
        "<code>host:port:user:password</code>\n\n/cancel برای انصراف")


@dp.message(TunReg.iran)
async def tun_reg_iran(msg: Message, state: FSMContext):
    ssh = _parse_ssh(msg.text)
    if not ssh:
        await msg.answer("فرمت درست نبود: <code>host:port:user:password</code>")
        return
    await state.update_data(iran=ssh)
    try:
        await msg.delete()
    except Exception:
        pass
    await state.set_state(TunReg.foreign)
    await msg.answer("۲/۴ — دسترسی <b>سرور خارج</b> (آن سر تانل):\n"
                     "<code>host:port:user:password</code>")


@dp.message(TunReg.foreign)
async def tun_reg_foreign(msg: Message, state: FSMContext):
    ssh = _parse_ssh(msg.text)
    if not ssh:
        await msg.answer("فرمت درست نبود.")
        return
    await state.update_data(foreign=ssh)
    try:
        await msg.delete()
    except Exception:
        pass
    await state.set_state(TunReg.kind)
    b = InlineKeyboardBuilder()
    b.button(text="GRE", callback_data="tunreg_kind:gre")
    b.button(text="paytun", callback_data="tunreg_kind:paytun")
    b.adjust(2)
    await msg.answer("۳/۴ — نوع تانل فعلی چیست؟", reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("tunreg_kind:"))
async def tun_reg_kind(cb: CallbackQuery, state: FSMContext):
    await state.update_data(kind=cb.data.split(":")[1])
    await cb.answer()
    await state.set_state(TunReg.ports)
    await cb.message.answer("۴/۴ — پورت‌هایی که از تانل رد می‌شوند "
                            "(با کاما، مثل <code>9093</code>):")


@dp.message(TunReg.ports)
async def tun_reg_ports(msg: Message, state: FSMContext):
    ports = ",".join(p.strip() for p in msg.text.split(",") if p.strip().isdigit())
    if not ports:
        await msg.answer("حداقل یک پورت عددی بفرست.")
        return
    data = await state.get_data()
    await state.clear()
    iran, foreign, kind = data["iran"], data["foreign"], data["kind"]
    # Registered, not built: the tunnel already exists out there. Only the two
    # endpoints are recorded, which is everything a later rebuild needs.
    tid = st.add_tunnel(kind, iran["host"], foreign["host"], ports,
                        {"iran": iran, "foreign": foreign, "registered": True})
    note = await msg.answer("ثبت شد. در حال تست از داخل ایران…")
    try:
        ok = await tunnelwatch.probe(st, iran["host"], ports.split(",")[0])
    except Exception as e:
        await note.edit_text(f"✅ تانل ثبت شد (id={tid})\n"
                             f"⚠️ تست نشد: <code>{html.escape(str(e)[:160])}</code>",
                             reply_markup=kb_tun())
        return
    await note.edit_text(
        f"✅ <b>تانل ثبت شد</b> (id={tid})\n"
        f"ایران <code>{html.escape(iran['host'])}</code> ← "
        f"خارج <code>{html.escape(foreign['host'])}</code> · {kind} · {ports}\n\n"
        + ("🟢 از ایران جواب می‌دهد." if ok else "🔴 از ایران جواب نمی‌دهد.")
        + "\n\n<i>حالا لینک ساب را دوباره بفرست تا کانفیگ‌های تانلی شناسایی شوند.</i>",
        reply_markup=kb_tun())


async def _repair_tunnel(target, log_fn):
    """
    Bring a tunnelled config back.

    The account is examined before the tunnel itself: several tunnels usually
    share one provider account, so a suspension takes them all down together and
    they have to be moved together. Only after that is ruled out is the single
    tunnel rebuilt, cheapest remedy first.
    """
    jump = st.jump()
    rec = st.tunnel(target.get("tunnel_id")) if target.get("tunnel_id") else None
    if not rec:
        ips = await replacer.resolve(target["host"])
        rec = tunnelwatch.tunnel_for_ip(st, ips[0]) if ips else None
    if not rec:
        raise RuntimeError("تانلی برای این کانفیگ ثبت نشده")

    acc, fsrv, _ = await tunnelwatch.foreign_account(st, rec)
    if acc and fsrv:
        _remember_foreign(rec, acc, fsrv)
    if acc is None:
        # The foreign server could not be placed in any account. That is either
        # a server deleted by hand - which the rebuild below handles - or an
        # account we were refused, in which case rebuilding is impossible: we
        # can neither inspect the machine nor create its replacement. Rebuilding
        # anyway wipes the Iran side first, so the config goes down again on
        # every pass and never comes back. Say what is broken instead.
        blocked = await tunnelwatch.unreadable_accounts(st)
        # Only an account that answered and refused us is a reason to rebuild
        # elsewhere. One that simply failed to answer gets another pass.
        dead = [b for b in blocked if b[2]]
        flaky = [b for b in blocked if not b[2]]
        if flaky and not dead:
            note = ("⏳ اکانت‌هایی موقتاً جواب ندادند: "
                    + "، ".join(html.escape(str(a.get("label"))) for a, _r, _h in flaky)
                    + "\nاین معمولاً از پراکسی است و خودش برطرف می‌شود. "
                      "تعمیر به پاس بعدی موکول شد.")
            # No hold is set here: holds are keyed by watch-target id, and the
            # watchdog already applies one when a repair comes back incomplete.
            await log_fn(note)
            return {"banned": False, "note": note, "account": None,
                    "results": [{"iran": rec.get("iran_host"),
                                 "old_foreign": rec.get("foreign_host"),
                                 "ok": False, "how": "اکانت موقتاً جواب نداد"}]}
        blocked = dead
        if blocked:
            names = "، ".join(html.escape(str(a.get("label"))) for a, _r, _h in blocked)
            # An account we cannot read is an account we cannot use, which is
            # the same predicament as a banned one - so take the same way out:
            # rebuild the endpoint on a sibling account. What that needs is the
            # dead endpoint's provider, region and size, which is why they are
            # written down on every healthy pass.
            mem = _recall_foreign(rec)
            if mem is None and len(blocked) == 1:
                # Never written down, but only one account is dark, so that is
                # where it was. Borrow a working peer's region on that provider.
                only = blocked[0][0]
                peer = _peer_foreign_template(only.get("provider"),
                                             rec.get("foreign_host"))
                if peer:
                    mem = dict(peer, account_id=only.get("id"),
                               account_label=only.get("label"),
                               provider=only.get("provider"))
            if mem:
                await log_fn(
                    f"⛔️ اکانت «{html.escape(str(mem.get('account_label') or names))}» "
                    "از دسترس خارج است — سرور خارج روی یک اکانت دیگر ساخته می‌شود.")
                acc = {"id": mem.get("account_id"), "provider": mem.get("provider"),
                       "label": mem.get("account_label") or "?"}
                # Name the replacement after the tunnel it serves, not after
                # whichever peer's shape was borrowed - two servers built from
                # the same template would otherwise fight over one name, and
                # the panel rejects duplicates.
                own = st.get("tunfor_" + str(rec.get("iran_host") or ""))
                label = mem.get("label") if own else (
                    "tun-" + str(rec.get("iran_host") or "x").replace(".", "-"))
                fsrv = {"id": None, "ip": rec.get("foreign_host"),
                        "label": label, "region": mem.get("region"),
                        "plan": mem.get("plan")}
                banned, servers = True, []
                affected = [rec]
                note = (f"🚫 <b>اکانت «{html.escape(str(acc['label']))}» از دسترس "
                        "خارج شده</b> — تانل روی اکانت دیگری بازسازی می‌شود.")
                await log_fn(note)
                results = []
                for rec_i in affected:
                    try:
                        ok, how = await _repair_one_tunnel(
                            rec_i, acc, fsrv, banned, jump, log_fn)
                    except Exception as e:
                        ok, how = False, f"خطا: {type(e).__name__}: {str(e)[:140]}"
                    results.append({"iran": rec_i.get("iran_host"),
                                    "old_foreign": rec_i.get("foreign_host"),
                                    "ok": ok, "how": how})
                return {"banned": True, "note": note, "results": results,
                        "account": acc["label"]}
            note = (f"⛔️ <b>سرور خارج این تانل پیدا نشد و {len(blocked)} اکانت "
                    f"قابل خواندن نیست: {names}</b>\n"
                    f"<code>{html.escape(str(blocked[0][1]))}</code>\n\n"
                    "هیچ سابقه‌ای هم از منطقه و پلن این سرور نیست، پس جای "
                    "جایگزین معلوم نیست. تعمیر متوقف شد تا سمت ایران بی‌خود پاک نشود.")
            await log_fn(note)
            return {"banned": False, "note": note, "account": None,
                    "results": [{"iran": rec.get("iran_host"),
                                 "old_foreign": rec.get("foreign_host"),
                                 "ok": False,
                                 "how": "اکانت سرور خارج قابل دسترسی نیست"}]}
    banned, servers = (False, [])
    if acc:
        banned, servers = await tunnelwatch.account_is_banned(st, acc)

    affected = [rec]
    note = None
    if banned:
        affected = tunnelwatch.tunnels_on_account(st, servers) or [rec]
        note = (f"🚫 <b>اکانت «{html.escape(acc['label'])}» بن یا معلق شده</b> — "
                f"{len(affected)} تانل روی آن است و همه با هم افتاده‌اند.")
        await log_fn(note)

    results = []
    for rec_i in affected:
        try:
            ok, how = await _repair_one_tunnel(rec_i, acc, fsrv, banned, jump, log_fn)
        except Exception as e:
            ok, how = False, f"خطا: {str(e)[:160]}"
        results.append({"iran": rec_i.get("iran_host"),
                        "old_foreign": rec_i.get("foreign_host"),
                        "ok": ok, "how": how})
    return {"banned": banned, "note": note, "results": results,
            "account": (acc or {}).get("label")}


async def _try_rebuild(rec, log_fn, **kw):
    """
    One rung of the ladder, with its failure kept local.

    A rung that raises is a rung that failed, not a reason to abandon the
    ladder - the later rungs exist precisely because the earlier ones break.
    Letting the exception out meant the ladder was abandoned at rung one and
    the watchdog simply began again from rung one on its next pass, every few
    minutes, wiping the Iran side each time and never reaching the remedies
    that would have worked.
    """
    try:
        return await tunnelwatch.rebuild(st, rec, log=log_fn, **kw)
    except Exception as e:
        # A timeout stringifies to nothing at all, so the bare message produced
        # a warning with no content - the one failure mode that most needed
        # naming. The type is always there even when the text is not.
        detail = str(e)[:180] or "بدون پیام"
        await log_fn(f"⚠️ {html.escape(type(e).__name__)}: {html.escape(detail)}")
        return False, None


async def _repair_one_tunnel(rec, acc, fsrv, banned, jump, log_fn):
    """The retry ladder for a single tunnel. Returns (ok, description)."""
    kind = rec["kind"]
    other = tunnelwatch.OTHER_KIND[kind]

    # A live account usually just needs the tunnel stood back up, and the
    # transport swap costs nothing but a rebuild - so both come before paying
    # for a new server.
    if not banned:
        await log_fn(f"تلاش ۱: برپاسازی دوبارهٔ {kind} روی همان سرور")
        ok, _tid = await _try_rebuild(rec, log_fn, jump=jump)
        if ok:
            return True, f"{kind} دوباره برپا شد"
        rec = st.tunnel(rec["id"]) or rec

        await log_fn(f"تلاش ۲: تعویض نوع تانل به {other}")
        ok, tid = await _try_rebuild(rec, log_fn, kind=other, jump=jump)
        if ok:
            return True, f"نوع تانل به {other} عوض شد"
        rec = st.tunnel(tid or rec["id"]) or rec

    # Either the account is gone, or the tunnel will not come up on this IP.
    target_acc = acc
    if banned:
        target_acc = await replacer.sibling_account(
            st, acc["id"], acc["provider"], (fsrv or {}).get("region"))
        if not target_acc:
            # Every account of this provider is gone. Rather than fail and drop
            # the outage, park it and let the owner choose: wait for a new
            # account, or take a temporary home somewhere else right now.
            pid = st.add_pending({
                "kind": "tunnel", "tunnel_id": rec["id"],
                "provider": acc["provider"],
                "region": (fsrv or {}).get("region"),
                "plan": (fsrv or {}).get("plan"),
                "label": rec.get("iran_host"), "mode": None,
            })
            b = InlineKeyboardBuilder()
            b.button(text="⏳ اکانت اضافه می‌کنم، صبر کن",
                     callback_data=f"pend:wait:{pid}")
            b.button(text="🔀 موقتاً از اکانت‌های دیگر استفاده کن",
                     callback_data=f"pend:temp:{pid}")
            b.adjust(1)
            await bot.send_message(
                OWNER,
                f"🚨 <b>همهٔ اکانت‌های {acc['provider']} از دسترس خارج‌اند</b>\n\n"
                f"تانل ایران <code>{html.escape(str(rec.get('iran_host')))}</code> "
                f"جایی برای رفتن ندارد.\n\nچه کار کنم؟",
                reply_markup=b.as_markup())
            return False, "منتظر تصمیم تو — پیام انتخاب فرستادم"
        await log_fn(f"اکانت جایگزین (کم‌بارترین): «{target_acc['label']}»")
    if not target_acc or not fsrv:
        return False, "سرور خارجی این تانل در هیچ اکانتی پیدا نشد"

    old_ip = (fsrv or {}).get("ip") or rec.get("foreign_host")
    for attempt in (1, 2):
        await log_fn(f"ساخت سرور خارجی تازه (تلاش {attempt}/2)…")
        try:
            foreign, srv = await tunnelwatch.new_foreign_server(
                st, target_acc, fsrv, log_fn)
        except Exception as e:
            await log_fn(f"⚠️ سرور نو ساخته نشد: {html.escape(type(e).__name__)}: "
                         f"{html.escape(str(e)[:140])}")
            continue

        # A tunnel only carries traffic to the far end - it serves nothing
        # itself. A fresh server is a bare OS, so without the node software and
        # its panel registration nothing listens on the config's port there,
        # and the tunnel "works" while every customer on it gets nothing. It has
        # to be a connected node before the tunnel is pointed at it.
        if not await _make_foreign_node(srv, log_fn):
            await log_fn("نود روی سرور نو بالا نیامد؛ حذف و گرفتن سرور دیگر…")
            await _discard_foreign(target_acc, srv, log_fn)
            continue

        for k in (kind, other):
            ok, _tid = await tunnelwatch.rebuild(
                st, rec, kind=k, foreign=foreign, jump=jump, log=log_fn)
            if ok:
                # The old endpoint is only scrapped once its replacement works.
                # Its panel node goes too: left behind it sits in the node list
                # as a permanent error, hiding real failures among fake ones.
                if old_ip and old_ip != srv.get("ip"):
                    try:
                        await panel.delete_nodes_by_address(old_ip)
                    except Exception as e:
                        await log_fn(f"⚠️ حذف نود قدیمی از پنل نشد: {str(e)[:120]}")
                if not banned and (fsrv or {}).get("id"):
                    try:
                        await providers.Provider(acc).delete_server(fsrv["id"])
                        st.forget_server(acc["id"], fsrv["id"])
                    except Exception as e:
                        await log_fn(f"⚠️ حذف سرور قدیمی نشد: {str(e)[:120]}")
                return True, (f"سرور خارجی جدید <code>{foreign['host']}</code> "
                              f"با تانل {k}")
            rec = st.tunnel(rec["id"]) or rec
        await log_fn("این آی‌پی جواب نداد؛ حذف و گرفتن آی‌پی دیگر…")
        await _discard_foreign(target_acc, srv, log_fn)
    return False, "با دو آی‌پی تازه و هر دو نوع تانل هم بالا نیامد"


NODE_CONNECT_WAIT = 180


async def _make_foreign_node(srv, log_fn):
    """
    Install the node on a new tunnel endpoint and wait until the panel reports
    it connected. Returns False rather than raising: a server that will not
    take the node is a bad draw to be replaced, not a reason to stop repairing.
    """
    ip = srv.get("ip")
    try:
        await log_fn("نصب نود روی سرور خارجی نو…")
        ca, key = await provision_node(ip, srv["root_password"], log_fn)
        await panel.add_node(name=str(srv.get("label") or ip), address=ip,
                             server_ca=ca, api_key=key, core_config_id=SNI_CORE_ID)
    except Exception as e:
        await log_fn(f"⚠️ نصب نود نشد: {html.escape(type(e).__name__)}: "
                     f"{html.escape(str(e)[:140])}")
        return False
    # Registered is not the same as serving: the panel still has to reach the
    # node and push the core config before the port is live.
    deadline = time.time() + NODE_CONNECT_WAIT
    status = None
    while time.time() < deadline:
        try:
            for n in await panel.list_nodes():
                if n.get("address") == ip:
                    status = n.get("status")
        except Exception:
            pass
        if status == "connected":
            await log_fn(f"✅ نود <code>{ip}</code> در پنل وصل شد.")
            return True
        await asyncio.sleep(10)
    await log_fn(f"⚠️ نود <code>{ip}</code> بعد از {NODE_CONNECT_WAIT} ثانیه "
                 f"وصل نشد (وضعیت: {html.escape(str(status))}).")
    return False


async def _discard_foreign(acc, srv, log_fn):
    """Throw a failed endpoint away completely: its panel node and the server."""
    try:
        await panel.delete_nodes_by_address(srv.get("ip"))
    except Exception as e:
        await log_fn(f"⚠️ حذف نود ناموفق: {str(e)[:120]}")
    await replacer.scrap(st, acc, srv, log_fn)


def _remember_foreign(rec, acc, fsrv):
    """
    Note which account a tunnel's foreign end sits on, and its shape.

    An account that stops answering stops telling us what it held, and that is
    exactly when we need to know: to rebuild the endpoint somewhere else we
    need its provider, its region and its size. Asking afterwards is too late,
    so it is written down on every healthy pass. Keyed by the Iran host, which
    is the one part of a tunnel that survives every rebuild.
    """
    if not (acc and fsrv and rec.get("iran_host")):
        return
    try:
        st.set("tunfor_" + str(rec["iran_host"]), json.dumps({
            "account_id": acc.get("id"), "account_label": acc.get("label"),
            "provider": acc.get("provider"), "region": fsrv.get("region"),
            "plan": fsrv.get("plan"), "label": fsrv.get("label"),
            "ip": fsrv.get("ip"),
        }))
    except Exception:
        pass


def _recall_foreign(rec):
    """What we last knew about this tunnel's foreign end, or None."""
    raw = st.get("tunfor_" + str(rec.get("iran_host") or ""))
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return d if d.get("provider") and d.get("region") and d.get("plan") else None
    except Exception:
        return None


def _peer_foreign_template(provider, exclude_ip=None):
    """
    The shape of another tunnel's foreign endpoint on the same provider.

    A last resort for a tunnel we never got to write down. Every other tunnel's
    endpoint was already chosen for its latency to Iran, so borrowing one of
    their regions restores service in a place known to work, rather than
    guessing at a datacenter that may be useless for this traffic.
    """
    for tid_rec in st.tunnels():
        if tid_rec.get("foreign_host") == exclude_ip:
            continue
        mem = _recall_foreign(tid_rec)
        if mem and mem.get("provider") == provider:
            return mem
    return None


REPAIR_HOLD_MINUTES = 45


def _repair_held(tid):
    """Minutes left before this config may be repaired again, 0 if free.

    Every repair wipes both ends before rebuilding, so a repair that cannot
    succeed is not merely useless - it takes the config down again on each
    pass. A daily cap alone does not help: at a five-minute watch interval it
    permits hours of that. Whatever the cause, one failure buys quiet."""
    import time as _t
    until = st.get(f"repair_hold_{tid}")
    left = (int(until) - int(_t.time())) / 60 if until else 0
    return max(0, int(left + 0.5))


def _hold_repair(tid, minutes=REPAIR_HOLD_MINUTES):
    import time as _t
    st.set(f"repair_hold_{tid}", int(_t.time()) + minutes * 60)


def _clear_repair_hold(tid):
    st.set(f"repair_hold_{tid}", 0)


def _replace_budget(tid) -> int:
    """
    How many rebuilds this config has left today.

    A whole datacenter can be filtered at once. Without a cap, the watchdog
    would answer that by building server after server, all of them equally
    filtered, and hand the owner a bill instead of a fix.
    """
    import time as _t
    log_ = st.get(f"repl_log_{tid}")
    day = _t.strftime("%Y-%m-%d")
    if not log_ or not log_.startswith(day):
        return MAX_REPLACE_PER_DAY
    used = int(log_.split(":", 1)[1])
    return max(0, MAX_REPLACE_PER_DAY - used)


def _spend_replace(tid):
    import time as _t
    day = _t.strftime("%Y-%m-%d")
    log_ = st.get(f"repl_log_{tid}")
    used = int(log_.split(":", 1)[1]) + 1 if (log_ and log_.startswith(day)) else 1
    st.set(f"repl_log_{tid}", f"{day}:{used}")


async def _replace_target(t, log_fn):
    """
    Rebuild the server behind a broken config and move its subdomain over.

    Order matters: the new node is proven working before the old one is torn
    down, so a failed rebuild costs money but never availability.
    """
    fqdn = t["host"]
    if replacer.is_ip(fqdn):
        raise RuntimeError("این کانفیگ با آی‌پی خام آدرس‌دهی شده؛ "
                           "جایگزینی بی‌صدا ممکن نیست")
    ips = await replacer.resolve(fqdn)
    if not ips:
        raise RuntimeError("دامنه resolve نشد")
    old_ip = ips[0]

    await log_fn(f"سرور پشت <code>{html.escape(fqdn)}</code> = <code>{old_ip}</code>")
    acc, old, banned = await replacer.find_server(st, old_ip)
    if not acc:
        raise RuntimeError(f"سروری با آی‌پی {old_ip} در هیچ اکانتی پیدا نشد "
                           f"(اکانتش را به ربات اضافه کن تا بتوانم جایگزین کنم)")

    target_acc, ban_note = acc, None
    if banned:
        ban_note = (f"🚫 <b>اکانت «{html.escape(acc['label'])}» بن یا معلق شده</b> — "
                    f"همهٔ سرورهایش با هم خاموش‌اند.")
        await log_fn(ban_note + " دنبال اکانت دیگر در همان دیتاسنتر…")
        sib = await replacer.sibling_account(st, acc["id"], acc["provider"],
                                             old.get("region"))
        if not sib:
            raise RuntimeError(
                f"اکانت «{acc['label']}» بن شده و هیچ اکانت دیگری برای "
                f"{old.get('region')} باقی نمانده")
        target_acc = sib
        await log_fn(f"اکانت جایگزین (کم‌بارترین اکانت همان دیتاسنتر): "
                     f"«{html.escape(sib['label'])}»")

    # Hunt for an IP that Iran can actually reach.
    #
    # Vultr hands out addresses from many ranges and only some are blocked, so
    # the answer to a blocked one is simply to ask for another. The test is
    # done on port 22 BEFORE anything is installed: a blocked IP is blocked for
    # every port, so this rejects a bad address in about forty seconds instead
    # of after a three-minute node install. A rejected server is destroyed
    # immediately, so a long hunt costs pennies of hourly billing.
    srv = None
    for attempt in range(1, IP_HUNT_ATTEMPTS + 1):
        cand = await replacer.build_replacement(st, target_acc, old, log_fn)
        await log_fn(f"تست آی‌پی <code>{cand['ip']}</code> از داخل ایران "
                     f"(تلاش {attempt}/{IP_HUNT_ATTEMPTS})…")
        ok = await replacer.wait_port(cand["ip"], 22, tries=20, delay=8)
        if not ok:
            await log_fn("سرور بالا نیامد؛ حذف و تلاش دیگر.")
            await replacer.scrap(st, target_acc, cand, log_fn)
            continue
        res = await watchdog.run_probes(
            st.cfscan()["ssh"], st.jump(),
            [{"id": 0, "label": "ip-check", "host": cand["ip"], "port": 22,
              "tls": False}])
        reach = res and (res[0].get("tcp_ratio") or 0) >= 0.5
        if reach:
            await log_fn(f"✅ آی‌پی <code>{cand['ip']}</code> از ایران در دسترس است.")
            srv = cand
            break
        await log_fn(f"⛔️ <code>{cand['ip']}</code> از ایران بلاک است؛ "
                     f"حذف و گرفتن آی‌پی دیگر…")
        await replacer.scrap(st, target_acc, cand, log_fn)
    if srv is None:
        raise RuntimeError(f"بعد از {IP_HUNT_ATTEMPTS} تلاش، آی‌پی تمیزی در "
                           f"{old.get('region')} پیدا نشد")

    await log_fn("نصب و نود کردن سرور نو…")
    server_ca, api_key = await provision_node(srv["ip"], srv["root_password"], log_fn)
    await panel.add_node(name=str(srv.get("label") or srv["ip"]),
                         address=srv["ip"], server_ca=server_ca,
                         api_key=api_key, core_config_id=SNI_CORE_ID)
    await log_fn("نود اضافه شد. انتقال دامنه…")
    await _apply_ip(fqdn, srv["ip"])

    # Prove it from Iran before dismantling anything.
    await log_fn("تست کانفیگ جدید از داخل ایران…")
    await asyncio.sleep(20)
    probe_t = dict(t)
    probe_t["host"] = srv["ip"]      # test the new box directly; DNS may still be cached
    res = await watchdog.run_probes(st.cfscan()["ssh"], st.jump(), [probe_t])
    verdict = (res[0].get("verdict") if res else "down")
    healthy = verdict == "healthy"

    if healthy:
        await log_fn("سرور نو سالم است. حذف سرور قدیمی…")
        try:
            await panel.delete_nodes_by_address(old_ip, name=str(old.get("label")))
            await providers.Provider(acc).delete_server(old["id"])
            st.forget_server(acc["id"], old["id"])
        except Exception as e:
            await log_fn(f"⚠️ سرور نو کار می‌کند ولی حذف قدیمی نشد: "
                         f"{html.escape(str(e)[:150])}")
    else:
        # The replacement is no better than what it replaced - usually a fresh
        # IP that is blocked just like the old one. Roll the whole attempt back
        # rather than leaving it running: three retries a day would otherwise
        # quietly leave three billable, useless servers behind.
        await log_fn(f"⚠️ سرور نو هم سالم نشد ({verdict}). عقب‌گرد…")
        try:
            await _apply_ip(fqdn, old_ip)
            await log_fn("دامنه به آی‌پی قبلی برگشت.")
        except Exception as e:
            await log_fn(f"⚠️ برگرداندن دامنه نشد: {html.escape(str(e)[:120])}")
        try:
            await panel.delete_nodes_by_address(srv["ip"],
                                                name=str(srv.get("label")))
        except Exception as e:
            await log_fn(f"⚠️ حذف نود ناموفق: {html.escape(str(e)[:120])}")
        try:
            await providers.Provider(target_acc).delete_server(srv["id"])
            st.forget_server(target_acc["id"], srv["id"])
            await log_fn("سرور ناموفق حذف شد (هزینه‌ای روی دستت نماند).")
        except Exception as e:
            await log_fn(f"⚠️ حذف سرور ناموفق نشد — دستی چکش کن: "
                         f"{html.escape(str(e)[:120])}")

    return {"fqdn": fqdn, "old_ip": old_ip, "old_label": old.get("label"),
            "old_account": acc["label"], "new_ip": srv["ip"],
            "new_label": srv.get("label"), "new_account": target_acc["label"],
            "region": old.get("region"), "plan": old.get("plan"),
            "healthy": healthy, "verdict": verdict, "ban_note": ban_note}


async def _heal_target(t, log_fn):
    """A CDN-fronted config went bad: find a fresh clean IP and repoint it."""
    scan = st.cfscan()
    ssh = scan.get("ssh")
    if not (ssh and st.cf_token() and t.get("fqdn")):
        return None
    results, _tail = await cfscanner.run_scan(ssh, st.jump(), log_fn,
                                              per_24=1, rounds=8, final=10)
    if not results:
        return None
    best = results[0]
    await _apply_ip(t["fqdn"], best["ip"])
    return best


async def _do_watch(*, alert: bool):
    """One probe round. Returns the results; alerts and heals when asked."""
    cfg = st.cfscan()
    ssh = cfg.get("ssh")
    if not ssh:
        raise RuntimeError("سرور تست ایران تنظیم نشده")
    targets = st.watch_targets()
    results = await watchdog.run_probes(ssh, st.jump(), targets)
    st.set_watch_last(results)

    events, new_state = watchdog.evaluate(results, st.watch_state())
    st.set_watch_state(new_state)
    if not alert:
        return results

    by_id = {t["id"]: t for t in targets}
    by_res = {str(r.get("id")): r for r in results}

    # --- 1. say what changed --------------------------------------------
    for ev in events:
        r = ev["target"]
        name = html.escape(str(r.get("label")))
        if ev["kind"] == "recovered":
            await bot.send_message(
                OWNER, f"🟢 <b>{name}</b> برگشت\n{watchdog.describe(r)}")
        else:
            await bot.send_message(
                OWNER, f"⚠️ <b>{name}</b> مشکل دارد\n"
                       f"<code>{html.escape(str(r.get('host')))}:{r.get('port')}</code>\n"
                       f"{watchdog.describe(r)}")

    # --- 2. repair, driven by current state, not by this round's events ---
    # A config that was already broken when auto-repair got switched on has no
    # "it just broke" event to react to, and a repair that did not work needs
    # retrying on later rounds. Both are state, not transitions.
    state = st.watch_state()
    for t in targets:
        s = state.get(str(t["id"]), {})
        if not (s.get("firing") and s.get("verdict") in watchdog.BAD):
            continue
        r = by_res.get(str(t["id"]))
        if not r:
            continue
        name = html.escape(str(r.get("label")))
        # A filtered or dead CDN endpoint is the one case we can actually fix
        # ourselves: swap in a fresh clean IP instead of just complaining.
        if t.get("heal") and t.get("fqdn"):
            await bot.send_message(
                OWNER, f"♻️ <b>{name}</b> خراب است — در حال پیدا کردن آی‌پی تمیز تازه…")
            try:
                async def qlog(x):
                    log.info("heal %s: %s", name, x)
                best = await _heal_target(t, qlog)
            except Exception as e:
                await bot.send_message(
                    OWNER, f"❌ خوددرمانی <b>{name}</b> نشد: "
                           f"<code>{html.escape(str(e)[:200])}</code>")
                continue
            if best:
                await bot.send_message(
                    OWNER, f"✅ <b>{name}</b> — آی‌پی تازه پشت "
                           f"<code>{html.escape(t['fqdn'])}</code> نشست:\n"
                           f"<code>{best['ip']}</code>\n{_fmt_metrics(best)}")
            else:
                await bot.send_message(OWNER, f"⚠️ برای <b>{name}</b> آی‌پی تمیزی پیدا نشد.")

        elif (st.watch_cfg().get("auto_replace") and t.get("kind") == "tunnel"):
            budget = _replace_budget(t["id"])
            if budget <= 0:
                continue
            held = _repair_held(t["id"])
            if held:
                # Still in the quiet period a failed repair bought. Say nothing:
                # the failure was already reported, and repeating it every few
                # minutes would bury everything else.
                continue
            await bot.send_message(
                OWNER, f"🔧 <b>{name}</b> (کانفیگ تانل) خراب است — "
                       f"{CONFIRM_TRIES} تست تأیید با فاصلهٔ یک دقیقه…")
            if not await _confirm_down(t):
                await bot.send_message(
                    OWNER, f"🟢 <b>{name}</b> در تست‌های تأیید برگشت — "
                           f"اختلال گذرا بود، دست به سرور نزدم.")
                continue
            _spend_replace(t["id"])

            async def tlog(x):
                log.info("tunnel-repair %s: %s", name, x)

            try:
                info = await _repair_tunnel(t, tlog)
            except Exception as e:
                _hold_repair(t["id"])
                await bot.send_message(
                    OWNER, f"❌ <b>تعمیر تانل {name} نشد</b>\n"
                           f"<code>{html.escape(str(e)[:300])}</code>\n\n"
                           f"<i>{REPAIR_HOLD_MINUTES} دقیقه دیگر دوباره تلاش "
                           f"می‌کنم؛ تا آن موقع دست به این تانل نمی‌زنم.</i>")
                continue
            lines = []
            if info.get("note"):
                lines.append(info["note"])
            good = sum(1 for r in info["results"] if r["ok"])
            if good == len(info["results"]):
                _clear_repair_hold(t["id"])
            else:
                # Something did not come back. Buy quiet before trying again:
                # the next attempt would wipe both ends first, taking down
                # whatever this one did manage to restore.
                _hold_repair(t["id"])
            lines.append(f"{'✅' if good == len(info['results']) else '⚠️'} "
                         f"<b>تعمیر تانل</b> — {good} از {len(info['results'])} برگشت")
            if good != len(info["results"]):
                lines.append(f"<i>{REPAIR_HOLD_MINUTES} دقیقه صبر می‌کنم و "
                             f"دوباره تلاش می‌کنم.</i>")
            for r in info["results"]:
                mark = "✅" if r["ok"] else "❌"
                lines.append(f"{mark} ایران <code>{r['iran']}</code> ← "
                             f"خارج <code>{r['old_foreign']}</code>\n"
                             f"     {html.escape(str(r['how']))}")
            await bot.send_message(OWNER, "\n".join(lines))

        elif st.watch_cfg().get("auto_replace") and t.get("source") == "sub":
            # A direct config is broken: rebuild the server behind it.
            budget = _replace_budget(t["id"])
            if budget <= 0:
                # Said once per day: the round repeats every few minutes and
                # repeating this with it would be noise, not information.
                import time as _t
                day = _t.strftime("%Y-%m-%d")
                if st.get(f"repl_capmsg_{t['id']}") != day:
                    st.set(f"repl_capmsg_{t['id']}", day)
                    await bot.send_message(
                        OWNER, f"⏸ <b>{name}</b> — امروز {MAX_REPLACE_PER_DAY} بار "
                               f"تلاش شد و آی‌پی تمیزی در این لوکیشن پیدا نشد؛ "
                               f"تا فردا خودکار تلاش نمی‌کنم. بهتر است لوکیشن "
                               f"یا پرووایدر این کانفیگ را عوض کنیم.")
                continue
            await bot.send_message(
                OWNER, f"🔍 <b>{name}</b> خراب است — {CONFIRM_TRIES} تست تأیید "
                       f"با فاصلهٔ یک دقیقه قبل از هر اقدامی…")
            if not await _confirm_down(t):
                await bot.send_message(
                    OWNER, f"🟢 <b>{name}</b> در تست‌های تأیید برگشت — "
                           f"اختلال گذرا بود، سرور را عوض نکردم.")
                continue
            await bot.send_message(OWNER, "تأیید شد که واقعاً قطع است. "
                                          "شروع جایگزینی سرور…")
            lines = []

            async def rlog(x):
                lines.append(str(x))
                log.info("replace %s: %s", name, x)

            _spend_replace(t["id"])
            try:
                info = await _replace_target(t, rlog)
            except Exception as e:
                await bot.send_message(
                    OWNER, f"❌ <b>جایگزینی {name} نشد</b>\n"
                           f"<code>{html.escape(str(e)[:300])}</code>")
                continue
            head = ("✅ <b>سرور جایگزین شد</b>" if info["healthy"]
                    else "⚠️ <b>سرور نو هم از ایران کار نکرد — عقب‌گرد شد</b>")
            body = (f"{head}\n\n"
                    f"🔗 کانفیگ: <b>{name}</b>\n"
                    f"🌐 دامنه: <code>{html.escape(info['fqdn'])}</code>\n\n"
                    f"قدیمی: <code>{info['old_ip']}</code> "
                    f"({html.escape(str(info['old_label']))}) — "
                    f"اکانت «{html.escape(info['old_account'])}»\n"
                    f"جدید: <code>{info['new_ip']}</code> "
                    f"({html.escape(str(info['new_label']))}) — "
                    f"اکانت «{html.escape(info['new_account'])}»"
                    f"{'' if info['healthy'] else ' <i>(حذف شد)</i>'}\n"
                    f"📍 {info['region']} · {info['plan']}\n\n"
                    f"باقی‌ماندهٔ جایگزینی امروز برای این کانفیگ: "
                    f"{_replace_budget(t['id'])}")
            if info.get("ban_note"):
                body = info["ban_note"] + "\n\n" + body
            await bot.send_message(OWNER, body)
    return results


@dp.callback_query(F.data.startswith("pend:"))
async def pend_choice(cb: CallbackQuery):
    _, mode, pid = cb.data.split(":")
    pid = int(pid)
    row = next((r for r in st.pending() if r["id"] == pid), None)
    if not row:
        await cb.answer("این مورد دیگر معلق نیست.", show_alert=True)
        return
    st.update_pending(pid, mode=mode)
    await cb.answer()
    if mode == "wait":
        await cb.message.edit_text(
            f"⏳ باشه، صبر می‌کنم.\n\nهر وقت یک اکانت "
            f"<b>{row['provider']}</b> اضافه کردی، خودم بلافاصله جایگزینی را "
            f"شروع می‌کنم — لازم نیست چیزی بگویی.")
        return
    await cb.message.edit_text("🔀 باشه، الان موقتاً روی اکانت دیگری برپا می‌کنم…")
    try:
        ok, how = await _run_pending(row, temporary=True)
    except Exception as e:
        await bot.send_message(OWNER, f"❌ برپاسازی موقت نشد: "
                                      f"<code>{html.escape(str(e)[:250])}</code>")
        return
    await bot.send_message(
        OWNER, (f"{'✅' if ok else '❌'} <b>برپاسازی موقت</b> — {how}\n\n"
                f"<i>به محض اینکه یک اکانت {row['provider']} اضافه کنی، "
                f"خودم برش می‌گردانم روی آن.</i>" if ok else f"❌ {how}"))


async def _run_pending(row, *, temporary: bool):
    """
    Finish a parked tunnel repair.

    `temporary` means: settle for any healthy account now, and remember that
    this tunnel is living somewhere it does not belong so it can be moved home
    as soon as the owner's provider is available again.
    """
    rec = st.tunnel(row["tunnel_id"])
    if not rec:
        st.delete_pending(row["id"])
        return False, "این تانل دیگر ثبت نیست"

    want = None if temporary else row["provider"]
    acc = await replacer.sibling_account(st, -1, want, row.get("region"))
    if not acc:
        return False, ("هنوز هیچ اکانت سالمی نیست" if temporary
                       else f"هنوز اکانت {row['provider']} اضافه نشده")

    template = {"region": row.get("region"), "plan": row.get("plan"),
                "label": rec.get("foreign_host") or "tunnel"}

    async def plog(x):
        log.info("pending %s: %s", row["id"], x)

    foreign, srv = await tunnelwatch.new_foreign_server(st, acc, template, plog)
    for k in (rec["kind"], tunnelwatch.OTHER_KIND[rec["kind"]]):
        ok, _tid = await tunnelwatch.rebuild(st, rec, kind=k, foreign=foreign,
                                             jump=st.jump(), log=plog)
        if ok:
            # Scrap whatever temporary home this tunnel had before.
            old = row.get("temp_server")
            if old:
                try:
                    oacc = st.account(old["account_id"])
                    if oacc:
                        await providers.Provider(oacc).delete_server(old["id"])
                        st.forget_server(oacc["id"], old["id"])
                except Exception as e:
                    await plog(f"حذف سرور موقت نشد: {str(e)[:120]}")
            if temporary:
                st.update_pending(row["id"], mode="temp",
                                  temp_server={"id": srv["id"],
                                               "account_id": acc["id"],
                                               "ip": srv["ip"]})
            else:
                st.delete_pending(row["id"])
            where = "موقت روی" if temporary else "روی"
            return True, (f"{where} «{acc['label']}» با تانل {k} — "
                          f"<code>{foreign['host']}</code>")
        rec = st.tunnel(rec["id"]) or rec
    await replacer.scrap(st, acc, srv, plog)
    return False, "تانل روی اکانت جایگزین هم بالا نیامد"


async def pending_scheduler():
    """
    Watch for the account the owner promised, and finish the parked repairs.

    Both parked states resolve the same way - the moment a healthy account of
    the wanted provider exists, the tunnel is (re)built on it: for 'wait' that
    ends the outage, for 'temp' it brings the tunnel back home and disposes of
    the stand-in.
    """
    await asyncio.sleep(60)
    while True:
        try:
            for row in st.pending():
                if row.get("mode") not in ("wait", "temp"):
                    continue
                acc = await replacer.sibling_account(st, -1, row["provider"],
                                                     row.get("region"))
                if not acc:
                    continue
                await bot.send_message(
                    OWNER, f"🎯 اکانت <b>{html.escape(acc['label'])}</b> "
                           f"({row['provider']}) پیدا شد — شروع جایگزینی…")
                ok, how = await _run_pending(row, temporary=False)
                await bot.send_message(
                    OWNER, f"{'✅' if ok else '❌'} <b>تانل "
                           f"<code>{html.escape(str(row.get('label')))}</code></b> — {how}")
        except Exception:
            log.exception("pending scheduler pass failed")
        await asyncio.sleep(120)


async def watch_scheduler():
    await asyncio.sleep(45)
    while True:
        try:
            cfg = st.watch_cfg()

            # Once a day, re-read the subscription: the owner changes domains,
            # and a watchdog guarding addresses nobody uses any more is worse
            # than none, because it looks like everything is fine.
            if st.sub_url() and time.time() - cfg["sub_sync_ts"] >= 86400:
                try:
                    res = await _sync_from_sub()
                    if res["added"] or res["removed"]:
                        parts = []
                        if res["added"]:
                            parts.append("افزوده: " + "، ".join(
                                html.escape(str(c["label"])) for c in res["added"][:8]))
                        if res["removed"]:
                            parts.append("حذف‌شده: " + "، ".join(
                                html.escape(str(t["label"])) for t in res["removed"][:8]))
                        await bot.send_message(
                            OWNER, "🔁 <b>کانفیگ‌ها از لینک ساب به‌روز شد</b>\n\n"
                                   + "\n".join(parts) +
                                   f"\n\nمجموع تحت نظر: {res['total']}")
                except Exception as e:
                    log.exception("sub sync failed")
                    await bot.send_message(
                        OWNER, "⚠️ خواندن روزانهٔ لینک ساب نشد: "
                               f"<code>{html.escape(str(e)[:180])}</code>")

            cfg = st.watch_cfg()
            if cfg["enabled"] and st.watch_targets() and st.cfscan().get("ssh"):
                if time.time() - cfg["last_ts"] >= cfg["interval_minutes"] * 60:
                    st.set_watch_cfg(last_ts=int(time.time()))
                    # A pass reaches Iran over SSH, and an SSH connect to a host
                    # that answers pings but drops the handshake never returns on
                    # its own. Without a ceiling, one such host stops the watchdog
                    # for good: every config goes unwatched and unrepaired, and
                    # nothing says so, because the loop is not crashed - it is
                    # waiting. A pass that overruns is abandoned; the next one
                    # starts clean a minute later.
                    try:
                        await asyncio.wait_for(
                            _do_watch(alert=True),
                            timeout=max(240, cfg["interval_minutes"] * 60 * 2),
                        )
                    except asyncio.TimeoutError:
                        log.error(
                            "watchdog pass abandoned after %ss - a probe target is "
                            "hanging; skipping to the next pass",
                            max(240, cfg["interval_minutes"] * 60 * 2),
                        )
        except Exception:
            log.exception("watchdog pass failed")
        await asyncio.sleep(60)



def _device_scoring(results, controls=()):
    """
    Judge a phone's results against that phone's own connection, not ours.

    Mobile internet here is slower and far more variable than the relay's line,
    so an absolute threshold either passes everything or fails everything
    depending on the handset. What actually carries information is the spread
    *within one session*: the same phone, on the same network, minutes apart,
    measuring twenty addresses. An address that is better than that phone's own
    median is better for that operator, whatever the absolute numbers were.

    Returns {ip: (good, rtt, rel)} where rel is the ratio to the median.
    """
    # The reference addresses are not candidates and must not colour the
    # comparison: the relay sits inside Iran and answers several times faster
    # than any Cloudflare edge, so leaving it in would drag the median down and
    # make every real address look bad against it.
    results = [r for r in results if r.get("ip") not in controls]
    live = [r for r in results if r.get("rtt_ms") and r.get("ok")]
    if not live:
        return {}
    rtts = sorted(r["rtt_ms"] for r in live)
    median = rtts[len(rtts) // 2]
    losses = sorted((r.get("loss") or 0) for r in live)
    median_loss = losses[len(losses) // 2]

    out = {}
    for r in results:
        ip = r.get("ip")
        if not ip:
            continue
        rtt = r.get("rtt_ms")
        loss = r.get("loss") or 0
        if not r.get("ok") or not rtt:
            out[ip] = (False, rtt, None)
            continue
        rel = rtt / median if median else 1.0
        # Within a sixth of this phone's own median is "as good as this network
        # gets"; losing much more than its own typical amount is not.
        good = rel <= 1.15 and loss <= max(0.25, median_loss + 0.10)
        out[ip] = (good, rtt, rel)
    return out


REPORT_TTL = 7 * 86400   # a verdict older than this says nothing about today


async def _refresh_probe_sni():
    """
    Find the name a customer's client actually puts in the handshake.

    For a CDN config the address and the server name are two different domains
    on purpose: the packets go to the address, which is where the clean IP is
    published, while the TLS handshake asks for something else entirely. Probing
    with the address - or worse, with a Cloudflare speedtest host - measures a
    handshake no customer ever makes, and the filtering we are trying to detect
    happens at exactly that step.

    Read from the panel rather than configured here, because the two must not be
    allowed to drift: the panel is where the value is actually set.
    """
    fqdn = (st.cfscan().get("fqdn") or "").lower()
    if not fqdn:
        return None
    try:
        panel = Panel(PANEL_URL, PANEL_USER, PANEL_PASS)
        for h in await panel.hosts():
            addrs = [str(a).lower() for a in (h.get("address") or [])]
            if any(fqdn in a for a in addrs):
                sni = [s for s in (h.get("sni") or []) if s]
                if sni:
                    if sni[0] != st.get("probe_sni"):
                        # Measurements taken under the old name are not
                        # measurements of the new test, so record when it
                        # changed and let the phones be asked again.
                        st.set("probe_sni", sni[0])
                        st.set("probe_sni_ts", int(time.time()))
                    return sni[0]
    except Exception:
        log.exception("could not read the CDN host's sni from the panel")
    return None


def _control_ips():
    """
    The reference address handed to the phones alongside the real candidates.

    A phone that failed everything has told us nothing about any address: its
    own data may simply have been broken at that moment, and nothing in the
    numbers distinguishes that from an operator blocking the lot. The way to
    tell them apart is to have it also measure something that must work
    whenever its connection does - the Iran relay it is already talking to. If
    even that failed, the round describes the handset, not Cloudflare.
    """
    host = PROBE_BASE.split("//", 1)[-1].split("/")[0].split(":")[0]
    try:
        import socket
        return [socket.gethostbyname(host)]
    except Exception:
        return []


def _report_trusted(rep, controls):
    """Whether a round says anything about the addresses. -> (trusted, why)."""
    res = rep.get("results") or []
    if not res:
        return False, "چیزی اندازه‌گیری نشده بود"
    if (rep.get("net") or "cellular") != "cellular":
        return False, "روی وای‌فای اندازه‌گیری شده بود، نه دیتای همراه"
    seen = [r for r in res if r.get("ip") in controls]
    if seen:
        if not any(r.get("ok") for r in seen):
            return False, ("سرور ایران هم از این گوشی جواب نداد — "
                           "اینترنت خودِ گوشی آن لحظه کار نمی‌کرده")
        return True, ""
    # An older round, measured before reference addresses were being sent. The
    # only thing left to go on is whether anything at all worked.
    if not any(r.get("ok") for r in res):
        return False, ("هیچ آدرسی جواب نداد و آن دور مرجعی برای مقایسه نداشت — "
                       "معلوم نیست تقصیر اپراتور بوده یا اینترنت گوشی")
    return True, ""


def _classify_reports():
    """(trusted, set_aside) - set_aside maps device -> (report, why)."""
    now = int(time.time())
    controls = set(st.scan_candidates().get("controls") or [])
    trusted, aside = {}, {}
    for d, r in st.device_reports().items():
        if now - (r.get("ts") or 0) >= REPORT_TTL:
            continue
        ok, why = _report_trusted(r, controls)
        if ok:
            trusted[d] = r
        else:
            aside[d] = (r, why)
    return trusted, aside


def _fresh_reports():
    """The rounds that are allowed to influence the choice."""
    return _classify_reports()[0]


SCAN_SAMPLE = 1000        # addresses the relay measures in one pass
PHONE_SHORTLIST = 50      # the best of a window, handed to the phones
PHONE_GRACE_MINUTES = 25  # how long a fresh list waits for the handsets
SCAN_GAP_MINUTES = 10     # between passes of the round-the-clock scan


def _record_blocked():
    """
    Note every address a trusted round could not complete.

    Only rounds that pass the trust gate count, so a handset with no signal
    cannot condemn an address it never really tried. What is recorded is a
    failure to finish the TLS handshake - which from a fixed line looks like
    nothing at all, and is the whole reason the phones exist.
    """
    controls = set(st.scan_candidates().get("controls") or [])
    bad, good = set(), set()
    for _d, r in _fresh_reports().items():
        for x in r.get("results") or []:
            ip = x.get("ip")
            if not ip or ip in controls:
                continue
            (good if x.get("ok") else bad).add(ip)
    # An address one operator refuses and another serves happily is not blocked
    # - it is simply worse on one network. Blacklisting on the union of the two
    # threw away addresses that were working for half the customers, and in one
    # case discarded a whole shortlist that had twenty-six usable addresses on
    # it because the other handset was having a bad hour.
    bad -= good
    if bad:
        st.mark_blocked(bad)
    return bad


def _phone_verdicts(since=0):
    """
    {device: {ip: (good, rtt, rel)}} for the rounds that are allowed to count.

    A round counts when it was measured on mobile data and the reference address
    answered - proof the handset's own connection was working, so that a phone
    with no signal cannot veto an address it never really reached.
    """
    controls = set(st.scan_candidates().get("controls") or [])
    return {d: _device_scoring(r.get("results", []), controls)
            for d, r in _fresh_reports().items()
            if int(r.get("ts") or 0) >= int(since or 0)}


REQUIRED_PHONES = 2          # handsets that must both approve an address
HEAD_TO_HEAD_TTL = 20 * 60   # reuse a relay comparison for this long
HEAD_TO_HEAD_MAX = 5         # candidates measured against the live address


def choose(results, live_ip=None, measured=None, since=0):
    """
    Whether to move the domain, and to which address.

        an address qualifies only if EVERY phone that measured this list rated
        it better than that phone's own median, and at least REQUIRED_PHONES
        phones did so in a round measured after the list was published;
        a qualifying address replaces the live one only if the relay measures
        it better than the live address, both measured in the same run.

    Anything short of that keeps the address already serving customers. A
    phone that is silent, measured an older list, or had its round set aside
    is not a vote for anything - and one phone alone is not enough, because an
    address that suits one operator can be filtered on the other.

    `measured` is {ip: metrics} from one relay run that covered the live address
    and the contenders. Without it, a qualifying round returns `needs_measure`
    and no change, so the caller can take that measurement first.

    Returns {change, entry, why, voters, needs_measure}.
    """
    ranked = [r for r in results if r.get("ip")]
    on_list = {r["ip"] for r in ranked}
    live_entry = (next((r for r in ranked if r["ip"] == live_ip), None)
                  or ({"ip": live_ip} if live_ip else None))

    def keep(why, voters=0, needs=None):
        return {"change": False, "entry": live_entry, "why": why,
                "voters": voters, "needs_measure": needs or []}

    if not ranked:
        return keep("لیست کاندید خالی است — آدرس فعلی ماند")

    # Only rounds measured after this list was published count. A report is
    # timestamped on arrival, and each phone keeps only its latest, so an older
    # one is about an older list - its opinion of an address that happens to be
    # on this list too was formed under different conditions.
    verdicts = {d: {ip: v for ip, v in vs.items() if ip in on_list}
                for d, vs in _phone_verdicts(since).items()}
    voters = [d for d, v in verdicts.items() if v]
    if len(voters) < REQUIRED_PHONES:
        return keep("فقط %d از %d گوشی این لیست را سنجیده؛ تعویض فقط با تأیید هر دو گوشی "
                    "— آدرس فعلی ماند" % (len(voters), REQUIRED_PHONES), len(voters))

    approved = []
    for r in ranked:
        opinions = [verdicts[d].get(r["ip"]) for d in voters]
        # Every voting phone must have actually tried it, and liked it.
        if any(o is None for o in opinions) or not all(o[0] for o in opinions):
            continue
        rels = [o[2] for o in opinions if o[2]]
        approved.append(((sum(rels) / len(rels)) if rels else 9, r))
    if not approved:
        return keep("هیچ آدرسی تأیید هر دو گوشی را نگرفت — آدرس فعلی ماند", len(voters))
    approved.sort(key=lambda x: x[0])

    if live_ip and any(r["ip"] == live_ip for _rel, r in approved):
        return keep("آدرس فعلی خودش مورد تأیید هر دو گوشی است", len(voters))

    contenders = [(rel, r) for rel, r in approved if r["ip"] != live_ip][:HEAD_TO_HEAD_MAX]
    if measured is None:
        return keep("در انتظار مقایسهٔ سرور با آدرس فعلی", len(voters),
                    [r["ip"] for _rel, r in contenders])

    live_m = measured.get(live_ip) if live_ip else None
    # A live address the relay could not reach at all is beaten by anything
    # that did answer.
    live_score = cfscanner.score(live_m) if live_m else float("inf")
    better = []
    for rel, r in contenders:
        m = measured.get(r["ip"])
        if m and cfscanner.score(m) < live_score:
            better.append((rel, cfscanner.score(m), r, m))
    if not better:
        return keep("%d آدرس تأیید هر دو گوشی را گرفت ولی در تست سرور هیچ‌کدام از آدرس فعلی "
                    "بهتر نبود — آدرس فعلی ماند" % len(contenders), len(voters))

    better.sort(key=lambda x: (x[0], x[1]))
    rel, score, r, m = better[0]
    entry = dict(r, **m)
    entry["ip"] = r["ip"]
    live_txt = ("%.0f" % live_score) if live_m else "بی‌پاسخ"
    why = ("هر دو گوشی تأییدش کردند (%.2f) و در تست سرور از آدرس فعلی بهتر بود "
           "(امتیاز %.0f در برابر %s)" % (rel, score, live_txt))
    return {"change": True, "entry": entry, "why": why,
            "voters": len(voters), "needs_measure": []}


async def _head_to_head(since, live_ip, ips):
    """
    Measure the live address and the contenders together, in one relay run.

    "Better than the address behind the domain" only means something when both
    were measured at the same moment on the same path; numbers from hours apart
    compare the time of day, not the addresses. Cached briefly, because the
    recheck runs every two minutes and the answer does not change that fast.
    Returns {ip: metrics}, or None when the measurement could not be taken.
    """
    key = "%s|%s|%s" % (since, live_ip or "", ",".join(sorted(ips)))
    try:
        cached = json.loads(st.get("scan_h2h") or "{}")
    except Exception:
        cached = {}
    if cached.get("key") == key and time.time() - (cached.get("ts") or 0) < HEAD_TO_HEAD_TTL:
        return cached.get("measured") or {}
    ssh = st.cfscan().get("ssh")
    if not ssh:
        return None
    only = ([live_ip] if live_ip else []) + [ip for ip in ips if ip != live_ip]

    async def hlog(t):
        log.info("head-to-head: %s", t)

    try:
        rows, _tail = await cfscanner.run_scan(ssh, st.jump(), hlog, only=only, final=len(only))
    except Exception:
        log.exception("head-to-head measurement failed")
        return None
    measured = {r["ip"]: {k: v for k, v in r.items() if k != "ip"} for r in rows if r.get("ip")}
    st.set("scan_h2h", json.dumps({"key": key, "ts": int(time.time()), "measured": measured}))
    log.info("head-to-head %s -> %s", key,
             {ip: round(cfscanner.score(m)) for ip, m in measured.items()})
    return measured


async def decide(results, live_ip, cand):
    """choose(), taking the relay comparison first when the phones have agreed."""
    since = int(cand.get("ts") or 0)
    d = choose(results, live_ip, since=since)
    if not d["needs_measure"]:
        return d
    measured = await _head_to_head(since, live_ip, d["needs_measure"])
    if measured is None:
        d["why"] = "مقایسهٔ سرور با آدرس فعلی انجام نشد — آدرس فعلی ماند"
        return d
    return choose(results, live_ip, measured=measured, since=since)


SILENT_PHONE_ALERT_GAP = 6 * 3600


async def _warn_silent_phones(cand, decision):
    """
    Say once in a while why the domain is not moving, when a phone is the reason.

    The rule needs both phones on every list, so one handset that stops
    measuring freezes the address indefinitely - silently, since nothing is
    broken on the server's side. A phone can keep pinging and still not measure
    (battery restrictions stop the scan but not the heartbeat), so what is
    checked is the measurement, not the ping.
    """
    if decision["voters"] >= REQUIRED_PHONES:
        return
    since = int(cand.get("ts") or 0)
    if not since or time.time() - since < PHONE_GRACE_MINUTES * 60:
        return
    if time.time() - int(st.get("silent_phone_alert_ts") or 0) < SILENT_PHONE_ALERT_GAP:
        return
    seen = st.devices_seen()
    reports = st.device_reports()
    if len(seen) < REQUIRED_PHONES:
        return
    missing = [(d, info) for d, info in seen.items()
               if int((reports.get(d) or {}).get("ts") or 0) < since]
    if not missing:
        return
    st.set("silent_phone_alert_ts", int(time.time()))
    lines = []
    for d, info in missing:
        last = int((reports.get(d) or {}).get("ts") or 0)
        lines.append("• %s — آخرین سنجش %s، آخرین تماس %s" % (
            html.escape(str(info.get("operator") or d)), _ago(last), _ago(info.get("ts"))))
    try:
        await bot.send_message(
            OWNER,
            "⏳ <b>تعویض آی‌پی متوقف است</b>\n\n"
            "آی‌پی دامنه فقط وقتی عوض می‌شود که هر دو گوشی لیست فعلی را بسنجند. "
            "این گوشی از انتشار لیست فعلی سنجشی نفرستاده:\n"
            + "\n".join(lines) +
            "\n\nتا گزارشش برسد، آدرس فعلی دامنه دست نمی‌خورد.")
    except Exception:
        log.exception("silent phone alert failed")


def verified_best():
    """
    The shortlist as the phones rated it - what `choose` sees, laid out for the
    panel.

    The universe is this cycle's shortlist and nothing else. An address the
    relay did not put forward this time is not a candidate, whatever a phone
    said about it six hours ago, so there is nothing here that the decision
    would not also act on.
    """
    cand = st.scan_candidates()
    metrics = cand.get("metrics") or {}
    on_list = set(cand.get("ips") or [])
    verdicts = {d: {ip: v for ip, v in vs.items() if ip in on_list}
                for d, vs in _phone_verdicts(int(cand.get("ts") or 0)).items()}
    voters = [d for d, v in verdicts.items() if v]
    reports = _fresh_reports()

    out = []
    for ip in cand.get("ips") or []:
        opinions = []
        for d in voters:
            v = verdicts[d].get(ip)
            if v is None:
                continue
            good, rtt, rel = v
            opinions.append({"device": d, "operator": reports[d].get("operator", "?"),
                             "ok": good, "rtt": rtt, "rel": rel})
        heard = len(opinions)
        agreed = (len(voters) >= REQUIRED_PHONES and heard == len(voters)
                  and all(o["ok"] for o in opinions))
        rels = [o["rel"] for o in opinions if o.get("rel")]
        out.append({
            "ip": ip,
            "verified": agreed,
            "rejected": heard > 0 and not agreed,
            "tested_by": heard,
            "relay_rtt": (metrics.get(ip) or {}).get("rtt"),
            "avg_rel": (sum(rels) / len(rels)) if rels else None,
            "operators": opinions,
        })

    def rank(e):
        # Vouched for first, then untried, then refused; inside each, the phones'
        # own rating leads and the relay's latency only breaks a tie.
        tier = 0 if e["verified"] else (2 if e["rejected"] else 1)
        return (tier, e["avg_rel"] if e["avg_rel"] is not None else 9,
                e["relay_rtt"] or 9999)
    out.sort(key=rank)
    return out


def _dev_label(dev, info):
    """What to call this handset: the owner's name if they gave one."""
    name = st.device_names().get(dev)
    op = info.get("operator") or "?"
    return f"{name} ({op})" if name else op


def _app_label(info):
    """The build a phone is running, when it is new enough to say."""
    v = info.get("app")
    return f" · نسخه {v}" if v else ""


def _net_label(info):
    """Whether the handset is on mobile data right now. Only rounds measured on
    mobile data count, so a phone parked on Wi-Fi is online but not measuring."""
    net = info.get("net")
    if net == "cellular":
        return " · دیتای همراه"
    if net == "wifi":
        return " · وای‌فای (اندازه‌گیری متوقف)"
    return ""


def _phone_status():
    """(online, offline) device rows. Online means heard from within one cycle."""
    import time as _t
    seen = st.devices_seen()
    # The phones ping every half hour, so silence for a bit over two of those is
    # a phone that is off or has no network - not one whose schedule drifted.
    # (Measurement runs twice a day; liveness is a separate, much cheaper thing.)
    cutoff = _t.time() - 75 * 60
    online, offline = [], []
    for dev, info in seen.items():
        (online if info.get("ts", 0) >= cutoff else offline).append((dev, info))
    online.sort(key=lambda x: -x[1].get("ts", 0))
    offline.sort(key=lambda x: -x[1].get("ts", 0))
    return online, offline


def _ago(ts):
    import time as _t
    if not ts:
        return "هرگز"
    m = int((_t.time() - ts) / 60)
    if m < 60:
        return f"{m} دقیقه پیش"
    h = m // 60
    return f"{h} ساعت پیش" if h < 48 else f"{h // 24} روز پیش"


@dp.callback_query(F.data == "scan_verified")
async def cb_scan_verified(cb: CallbackQuery):
    await cb.answer()
    online, offline = _phone_status()
    b = InlineKeyboardBuilder()
    lines = ["📱 <b>سنجش از گوشی‌ها</b>", ""]

    if not online and not offline:
        lines += [
            "هنوز هیچ گوشی‌ای وصل نشده.",
            "",
            f"آدرس: <code>{PROBE_BASE}</code>",
            f"توکن: <code>{html.escape(st.probe_token())}</code>",
            "",
            "<i>این دو را در اپ وارد کن.</i>",
        ]
    else:
        for dev, info in online:
            lines.append(f"🟢 <b>{html.escape(_dev_label(dev, info))}</b> — "
                         f"آنلاین ({_ago(info.get('ts'))}){_net_label(info)}"
                         f"{_app_label(info)}")
            b.button(text=f"📊 {_dev_label(dev, info)[:20]}",
                     callback_data=f"phone_detail:{dev[:48]}")
        for dev, info in offline:
            lines.append(f"🔴 <b>{html.escape(_dev_label(dev, info))}</b> — "
                         f"آخرین ارتباط {_ago(info.get('ts'))}")
            b.button(text=f"📊 {_dev_label(dev, info)[:20]} (آفلاین)",
                     callback_data=f"phone_detail:{dev[:48]}")

        # A round that is set aside must not simply vanish: silence here looks
        # exactly like a phone that never reported, and the difference between
        # "nothing to say" and "this handset's own connection was broken" is
        # the thing worth knowing.
        trusted_reps, aside_reps = _classify_reports()
        controls = set(st.scan_candidates().get("controls") or [])
        for dev, (rep, why) in sorted(aside_reps.items(),
                                      key=lambda x: -(x[1][0].get("ts") or 0)):
            res = rep.get("results") or []
            ok = sum(1 for r in res if r.get("ok"))
            lines.append(
                f"⛔️ <b>{html.escape(_dev_label(dev, rep))}</b> — "
                f"{ok} از {len(res)} آدرس ({_ago(rep.get('ts'))})؛ {why}. "
                "<i>در انتخاب دخالت داده نشد.</i>")
            lines.append("")

        # A trusted round that still reached nothing is the most informative
        # result of all and the easiest to miss: the handset's connection was
        # proven working against the reference address, and every candidate
        # still failed. That is the operator blocking them, not a bad phone.
        # It changes no choice - no other address would work for that operator
        # either, and vetoing them would break the operator that is fine - but
        # it is the one thing here worth acting on outside this bot.
        for dev, rep in sorted(trusted_reps.items(),
                               key=lambda x: -(x[1].get("ts") or 0)):
            res = [r for r in (rep.get("results") or [])
                   if r.get("ip") not in controls]
            if res and not any(r.get("ok") for r in res):
                sni = sum(1 for r in res if r.get("stage") == "sni")
                verdict = ("<b>روی نام دامنه فیلتر می‌کند، نه روی آی‌پی</b> — "
                           f"{sni} آدرس با نام دیگری باز شد"
                           if sni else
                           "<b>یعنی این اپراتور دارد فیلتر می‌کند</b> — "
                           "با عوض کردن آی‌پی حل نمی‌شود")
                lines.append(
                    f"🚫 <b>{html.escape(_dev_label(dev, rep))}</b> — اینترنت این "
                    f"گوشی سالم بود ولی هیچ‌کدام از {len(res)} آدرس کلادفلر جواب "
                    f"نداد ({_ago(rep.get('ts'))}). {verdict}.")
                lines.append("")

        rows = verified_best()
        ranked = [e for e in rows if e["tested_by"]]
        live = st.cfscan().get("last_best_ip")
        lines.append("")
        # Two handsets only add something while they sit on different networks.
        # On the same operator they measure the same route twice, and an address
        # "confirmed by both" says nothing at all about the other carriers.
        fresh = _fresh_reports()
        ops = sorted({r.get("operator") for r in fresh.values() if r.get("operator")})
        if len(fresh) > 1 and len(ops) < 2:
            who = html.escape("، ".join(ops) or "؟")
            lines.append("⚠️ <i>در آخرین اندازه‌گیری‌ها هر دو گوشی روی یک "
                         "اپراتور بوده‌اند (" + who + ") — "
                         "برای مقایسهٔ اپراتورها یکی را روی سیم‌کارت دیگری بگذار.</i>")
            lines.append("")
        if ranked:
            lines.append("<b>بهترین آی‌پی‌ها</b> <i>(نسبت به شبکهٔ خود هر گوشی — "
                         "نظر گوشی بر سرور مقدم است)</i>")
            for e in ranked[:6]:
                mark = "✅" if e["verified"] else "❌"
                if e["ip"] == live:
                    mark += "🌐"
                ops = "، ".join(
                    f"{html.escape(st.device_names().get(o['device']) or o['operator'])}: "
                    + ("خوب" if o["ok"] else "ضعیف")
                    + (f" ({o['rel']:.2f}×)" if o.get("rel") else "")
                    for o in e["operators"])
                lines.append(f"{mark} <code>{e['ip']}</code>\n    {ops}")
        else:
            lines.append("<i>گوشی‌ها هنوز روی آی‌پی‌های این اسکن گزارشی نداده‌اند.</i>")
        both = sum(1 for e in ranked if e["verified"])
        lines.append("")
        lines.append("<i>مورد تأیید همهٔ گوشی‌های گزارش‌دهنده: <b>" + str(both) +
                     "</b> از " + str(len(rows)) + " آدرس این دور — "
                     "انتخاب دامنه از میان همین‌هاست.</i>")

    lines.append("")
    lines.append(f"⏱ بازهٔ اجرا روی گوشی‌ها: هر <b>{st.probe_interval()}</b> ساعت")
    b.button(text="⏱ تغییر بازه", callback_data="phone_interval")
    b.button(text="🔑 آدرس و توکن", callback_data="phone_creds")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())


@dp.callback_query(F.data == "phone_creds")
async def cb_phone_creds(cb: CallbackQuery):
    await cb.answer()
    b = InlineKeyboardBuilder()
    b.button(text="🔙 بازگشت", callback_data="scan_verified")
    await cb.message.edit_text(
        "🔑 <b>تنظیمات اپ</b>\n\n"
        f"آدرس سرور:\n<code>{PROBE_BASE}</code>\n\n"
        f"توکن:\n<code>{html.escape(st.probe_token())}</code>\n\n"
        "<i>هر دو گوشی همین دو مقدار را می‌گیرند؛ خودشان از هم جدا شناخته می‌شوند.</i>",
        reply_markup=b.as_markup())


@dp.callback_query(F.data == "phone_interval")
async def cb_phone_interval(cb: CallbackQuery):
    await cb.answer()
    b = InlineKeyboardBuilder()
    for h in (6, 8, 12, 24):
        b.button(text=f"هر {h} ساعت", callback_data=f"phone_iv:{h}")
    b.button(text="🔙 بازگشت", callback_data="scan_verified")
    b.adjust(2, 2, 1)
    await cb.message.edit_text(
        "⏱ <b>بازهٔ اجرا روی گوشی‌ها</b>\n\n"
        "گوشی‌ها این را از سرور می‌خوانند، پس تغییرش خودکار اعمال می‌شود — "
        "حداکثر تا یک دور بعدی.\n\n"
        "<i>بازهٔ کوتاه‌تر یعنی بیدارشدن بیشتر رادیو و مصرف باتری بیشتر.</i>",
        reply_markup=b.as_markup())


@dp.callback_query(F.data.startswith("phone_iv:"))
async def cb_phone_iv_set(cb: CallbackQuery):
    h = int(cb.data.split(":")[1])
    st.set_probe_interval(h)
    await cb.answer(f"هر {h} ساعت")
    await cb_scan_verified(cb)


@dp.callback_query(F.data.startswith("phone_detail:"))
async def cb_phone_detail(cb: CallbackQuery):
    await cb.answer()
    dev = cb.data.split(":", 1)[1]
    reports = st.device_reports()
    rep = reports.get(dev)
    b = InlineKeyboardBuilder()
    b.button(text="✏️ تغییر نام", callback_data=f"phone_name:{dev[:48]}")
    b.button(text="🗑 حذف این گوشی", callback_data=f"phone_del:{dev[:48]}")
    b.button(text="🔙 بازگشت", callback_data="scan_verified")
    b.adjust(1)
    if not rep:
        await cb.message.edit_text("گزارشی از این گوشی نیست.", reply_markup=b.as_markup())
        return
    controls = set(st.scan_candidates().get("controls") or [])
    scoring = _device_scoring(rep.get("results", []), controls)
    seen_info = st.devices_seen().get(dev, {})
    live = "🟢 آنلاین" if seen_info and (time.time() - seen_info.get("ts", 0)) < 75 * 60 else "🔴 آفلاین"
    lines = [f"📊 <b>{html.escape(_dev_label(dev, {'operator': rep.get('operator')}))}</b>  {live}",
             f"<code>{html.escape(dev)}</code>",
             f"گزارش: {_ago(rep.get('ts'))}", ""]
    rows = sorted(rep.get("results", []),
                  key=lambda r: (not (scoring.get(r.get('ip'), (False,))[0]),
                                 r.get("rtt_ms") or 99999))
    for r in rows[:14]:
        ip = r.get("ip")
        good, rtt, rel = scoring.get(ip, (False, None, None))
        mark = "✅" if good else ("⚠️" if r.get("ok") else "❌")
        bits = []
        if rtt:
            bits.append(f"{rtt:.0f}ms")
        if rel:
            bits.append(f"{rel:.2f}× میانه")
        if r.get("loss"):
            bits.append(f"افت {r['loss']*100:.0f}%")
        lines.append(f"{mark} <code>{ip}</code> — {' · '.join(bits) or 'بی‌پاسخ'}")
    lines.append("")
    lines.append("<i>«میانه» یعنی نسبت به کندی معمول همین گوشی روی همین شبکه — "
                 "نه مقایسه با سرور.</i>")
    await cb.message.edit_text("\n".join(lines), reply_markup=b.as_markup())


class PhoneName(StatesGroup):
    waiting = State()


@dp.callback_query(F.data.startswith("phone_name:"))
async def cb_phone_name(cb: CallbackQuery, state: FSMContext):
    dev = cb.data.split(":", 1)[1]
    await state.set_state(PhoneName.waiting)
    await state.update_data(device=dev)
    await cb.answer()
    current = st.device_names().get(dev, "")
    await cb.message.answer(
        "✏️ یک نام برای این گوشی بفرست (مثلاً <code>گوشی خودم</code> یا "
        "<code>ایرانسل خانه</code>).\n\n"
        + (f"نام فعلی: <b>{html.escape(current)}</b>\n\n" if current else "")
        + "برای برداشتن نام، یک خط تیره بفرست: <code>-</code>")


@dp.message(PhoneName.waiting)
async def phone_name_set(msg: Message, state: FSMContext):
    d = await state.get_data()
    await state.clear()
    name = msg.text.strip()
    st.set_device_name(d["device"], "" if name == "-" else name)
    await msg.answer("✅ ثبت شد." if name != "-" else "✅ نام برداشته شد.")


@dp.callback_query(F.data.startswith("phone_del:"))
async def cb_phone_del(cb: CallbackQuery):
    st.forget_device(cb.data.split(":", 1)[1])
    await cb.answer("حذف شد.")
    await cb_scan_verified(cb)


async def main():
    asyncio.create_task(scan_scheduler())
    asyncio.create_task(phone_recheck())
    asyncio.create_task(watch_scheduler())
    asyncio.create_task(pending_scheduler())
    # Seed the Iran jump host once, from the env, if not already stored.
    if not st.jump() and os.environ.get("CLOUDBOT_JUMP"):
        h, p, u, pw = os.environ["CLOUDBOT_JUMP"].split(":", 3)
        st.set_jump(h, int(p), u, pw)
        log.info("iran jump host seeded: %s", h)
    probe_val = os.environ.get("CLOUDBOT_PROBE_BASE") or os.environ.get("CLOUDBOT_PROBE")
    if not probe_val or "example.com" in probe_val:
        log.warning(
            "Control probe host is unconfigured: CLOUDBOT_PROBE_BASE (or CLOUDBOT_PROBE) is unset, empty, or using placeholder. "
            "Phone consensus check cannot work because control addresses will never resolve."
        )
    log.info("cloudbot up, owner=%s panel=%s core=%s", OWNER, PANEL_URL, SNI_CORE_ID)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
