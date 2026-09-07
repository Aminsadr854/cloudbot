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

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cloudbot")

TOKEN = os.environ["CLOUDBOT_TOKEN"]
OWNER = int(os.environ["CLOUDBOT_OWNER"])
# The panel is configured from inside Telegram, not from the environment, so a
# fresh install needs nothing but a bot token and an owner id. Anything found in
# the environment is treated as a first-run seed and then lives in the encrypted
# store like every other credential.
PANEL_SEED = {
    "url": os.environ.get("CLOUDBOT_PANEL_URL", ""),
    "user": os.environ.get("CLOUDBOT_PANEL_USER", ""),
    "password": os.environ.get("CLOUDBOT_PANEL_PASS", ""),
    "core_id": os.environ.get("CLOUDBOT_CORE_ID", ""),
}

st = Store()
def panel_cfg() -> dict:
    return st.panel()


def core_id() -> int:
    """Which core config new nodes are attached to. 0 means 'let the panel decide'."""
    return int(panel_cfg().get("core_id") or 0)


class _PanelProxy:
    """
    Builds a Panel from stored settings on every call.

    A module-level Panel would freeze whatever was configured at import time,
    and this bot is meant to be configured after it starts - and reconfigured
    later without a restart.
    """

    def _live(self):
        c = panel_cfg()
        if not c.get("url"):
            raise RuntimeError("پنل هنوز تنظیم نشده — «⚙️ تنظیمات → 🎛 پنل»")
        return Panel(c["url"], c["user"], c["password"])

    def __getattr__(self, name):
        return getattr(self._live(), name)


panel = _PanelProxy()
bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())

PROVIDER_LABEL = {"linode": "🟢 Linode", "vultr": "🔵 Vultr", "hetzner": "🔴 Hetzner"}
PROXY_FAMILY_LABEL = {"default": "پیش‌فرض", "ipv4": "IPv4", "ipv6": "IPv6"}


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
    b.button(text="⚙️ تنظیمات", callback_data="settings")
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
    b.button(text="⚙️ تنظیمات", callback_data=f"accset:{acc['id']}")
    b.button(text="🔑 حذف اکانت", callback_data=f"delacc:{acc['id']}")
    b.button(text="🔙 اکانت‌ها", callback_data="accounts")
    b.adjust(2, 2, 1)
    return b.as_markup()


def proxy_summary(proxy):
    """Show a proxy endpoint without exposing its authentication details."""
    if not proxy:
        return "بدون پروکسی"
    value = proxy.split("://", 1)[-1]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return "پروکسی تنظیم شده"
        port = value[end + 2:].split(":", 1)[0] if value[end + 1:end + 2] == ":" else ""
        return f"{value[:end + 1]}:{port}" if port else value[:end + 1]
    bits = value.split(":", 2)
    return ":".join(bits[:2]) if len(bits) >= 2 else "پروکسی تنظیم شده"


def account_settings_text(acc):
    family = PROXY_FAMILY_LABEL.get(acc.get("proxy_family", "default"), "پیش‌فرض")
    return (
        "⚙️ <b>تنظیمات اکانت</b>\n\n"
        f"🏷 نام: <b>{html.escape(acc['label'])}</b>\n"
        f"☁️ ارائه‌دهنده: {PROVIDER_LABEL.get(acc['provider'], acc['provider'])}\n"
        f"🌐 پروکسی: <code>{html.escape(proxy_summary(acc['proxy']))}</code>\n"
        f"🔌 مسیر اتصال پراکسی: <b>{family}</b>\n"
        "🔐 توکن API: <i>ذخیره‌شده و رمزنگاری‌شده</i>"
    )


def kb_account_settings(acc):
    b = InlineKeyboardBuilder()
    b.button(text="✏️ تغییر نام", callback_data=f"accname:{acc['id']}")
    b.button(text="🌐 تغییر پراکسی", callback_data=f"prx:{acc['id']}")
    if acc["proxy"]:
        b.button(text="🗑 حذف پراکسی", callback_data=f"accprxclear:{acc['id']}")
    b.button(text="🔙 بازگشت", callback_data=f"acc:{acc['id']}")
    b.adjust(1)
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
    prx = proxy_summary(acc["proxy"])
    family = PROXY_FAMILY_LABEL.get(acc.get("proxy_family", "default"), "پیش‌فرض")
    await cb.message.edit_text(
        f"{PROVIDER_LABEL.get(acc['provider'])} <b>{html.escape(acc['label'])}</b>\n"
        f"🌐 پروکسی: <code>{html.escape(prx)}</code> · {family}",
        reply_markup=kb_account(acc))
    await cb.answer()


@dp.callback_query(F.data.startswith("accset:"))
async def cb_account_settings(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    acc = st.account(int(cb.data.split(":", 1)[1]))
    if not acc:
        await cb.answer("یافت نشد", show_alert=True)
        return
    await cb.message.edit_text(account_settings_text(acc), reply_markup=kb_account_settings(acc))
    await cb.answer()


# --------------------------------------------------------------------------
# add account
# --------------------------------------------------------------------------
class Add(StatesGroup):
    provider = State()
    label = State()
    token = State()
    proxy = State()
    proxy_family = State()


def kb_proxy_family(prefix: str):
    b = InlineKeyboardBuilder()
    b.button(text="پیش‌فرض", callback_data=f"{prefix}:default")
    b.button(text="IPv4", callback_data=f"{prefix}:ipv4")
    b.button(text="IPv6", callback_data=f"{prefix}:ipv6")
    b.adjust(3)
    return b.as_markup()


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


async def _finish_add(data, proxy, proxy_family, answer):
    try:
        acc = {"provider": data["provider"], "token": data["token"], "proxy": proxy,
               "proxy_family": proxy_family}
        who = await providers.Provider(acc).whoami()
    except Exception as e:
        log.exception("add-account validation failed (provider=%s proxy=%s)",
                      data.get("provider"), bool(proxy))
        await answer(f"❌ اتصال ناموفق بود:\n<code>{html.escape(str(e)[:350])}</code>\n\n"
                     "اگر پروکسی از نوع SOCKS است، جلوش <code>socks5://</code> بگذار. "
                     "وگرنه توکن را بررسی کن.")
        return
    st.add_account(data["label"], data["provider"], data["token"], proxy, proxy_family)
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
    await state.update_data(proxy=proxy)
    await state.set_state(Add.proxy_family)
    await msg.answer("اتصال به پراکسی با کدام IP برقرار شود؟", reply_markup=kb_proxy_family("addfam"))


@dp.callback_query(Add.proxy_family, F.data.startswith("addfam:"))
async def add_proxy_family(cb: CallbackQuery, state: FSMContext):
    family = cb.data.split(":", 1)[1]
    data = await state.get_data()
    await state.clear()
    await cb.message.edit_text("در حال تست اتصال…")
    await _finish_add(data, data["proxy"], family, cb.message.edit_text)
    await cb.message.answer("منو:", reply_markup=kb_main())
    await cb.answer()


@dp.callback_query(Add.proxy, F.data == "noproxy")
async def add_noproxy(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    await state.clear()
    await cb.message.edit_text("در حال تست اتصال…")
    await _finish_add(data, None, "default", cb.message.edit_text)
    await cb.message.answer("منو:", reply_markup=kb_main())
    await cb.answer()


# --------------------------------------------------------------------------
# proxy change
# --------------------------------------------------------------------------
class AccountSettings(StatesGroup):
    name = State()


@dp.callback_query(F.data.startswith("accname:"))
async def account_name_start(cb: CallbackQuery, state: FSMContext):
    acc_id = int(cb.data.split(":", 1)[1])
    acc = st.account(acc_id)
    if not acc:
        await cb.answer("یافت نشد", show_alert=True)
        return
    await state.set_state(AccountSettings.name)
    await state.update_data(acc_id=acc_id)
    b = InlineKeyboardBuilder()
    b.button(text="🔙 انصراف", callback_data=f"accset:{acc_id}")
    await cb.message.edit_text(
        f"نام جدید اکانت را بفرست.\n\nنام فعلی: <b>{html.escape(acc['label'])}</b>",
        reply_markup=b.as_markup())
    await cb.answer()


@dp.message(AccountSettings.name)
async def account_name_set(msg: Message, state: FSMContext):
    label = (msg.text or "").strip()
    if not label or len(label) > 80:
        await msg.answer("نام باید بین ۱ تا ۸۰ کاراکتر باشد.")
        return
    data = await state.get_data()
    await state.clear()
    st.set_account_label(data["acc_id"], label)
    acc = st.account(data["acc_id"])
    await msg.answer("✅ نام اکانت به‌روز شد.", reply_markup=kb_account_settings(acc))


class Proxy(StatesGroup):
    value = State()
    family = State()


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
    await state.update_data(proxy=proxy)
    await state.set_state(Proxy.family)
    await msg.answer("اتصال به پراکسی با کدام IP برقرار شود؟", reply_markup=kb_proxy_family("prxfam"))


@dp.callback_query(Proxy.family, F.data.startswith("prxfam:"))
async def prx_family(cb: CallbackQuery, state: FSMContext):
    family = cb.data.split(":", 1)[1]
    data = await state.get_data()
    account = st.account(data["acc_id"])
    await cb.message.edit_text("در حال تست اتصال…")
    try:
        await providers.Provider({**account, "proxy": data["proxy"], "proxy_family": family}).whoami()
    except Exception as e:
        await cb.message.edit_text(
            f"❌ اتصال ناموفق بود:\n<code>{html.escape(str(e)[:350])}</code>\n\n"
            "یک خانوادهٔ IP دیگر انتخاب کن یا با /start دوباره تلاش کن.",
            reply_markup=kb_proxy_family("prxfam"))
        await cb.answer()
        return
    await state.clear()
    st.set_proxy(data["acc_id"], data["proxy"], family)
    await cb.message.edit_text("✅ پروکسی به‌روز شد.", reply_markup=kb_account(st.account(data["acc_id"])))
    await cb.answer()


@dp.callback_query(Proxy.value, F.data == "prx_clear")
async def prx_clear(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    await state.clear()
    st.set_proxy(data["acc_id"], None, "default")
    await cb.message.edit_text("✅ پروکسی حذف شد.",
                               reply_markup=kb_account(st.account(data["acc_id"])))
    await cb.answer()


@dp.callback_query(F.data.startswith("accprxclear:"))
async def account_proxy_clear(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    acc_id = int(cb.data.split(":", 1)[1])
    st.set_proxy(acc_id, None, "default")
    acc = st.account(acc_id)
    await cb.message.edit_text("✅ پروکسی حذف شد.\n\n" + account_settings_text(acc),
                               reply_markup=kb_account_settings(acc))
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
    b = InlineKeyboardBuilder()
    b.button(text="🔌 نود کردن در پنل", callback_data=f"node:{acc_id}:{srv_id}")
    if acc["provider"] == "vultr":
        b.button(text="🔄 افزودن IPv4 جدید", callback_data=f"v4add:{acc_id}:{srv_id}")
        b.button(text="📌 افزودن Floating IP", callback_data=f"float:{acc_id}:{srv_id}")
    b.button(text="🗑 حذف سرور", callback_data=f"delsrv:{acc_id}:{srv_id}")
    b.button(text="🔙 سرورها", callback_data=f"srvs:{acc_id}")
    b.adjust(1)
    await cb.message.edit_text(
        f"🖥 <b>{html.escape(str(s['label']))}</b>\n"
        f"🌍 منطقه: <code>{s.get('region')}</code>\n"
        f"🔢 پلن: <code>{s.get('plan')}</code>\n"
        f"📡 آی‌پی: <code>{s.get('ip')}</code>\n"
        f"وضعیت: <b>{s.get('status')}</b>", reply_markup=b.as_markup())
    await cb.answer()


def _vultr_ip_value(result):
    """Read the allocated address from either documented Vultr response shape."""
    data = result.get("ipv4", result)
    return data.get("ip") or data.get("ip_address") or "در حال تخصیص"


async def _vultr_action_context(acc_id, srv_id):
    acc = st.account(int(acc_id))
    if not acc or acc["provider"] != "vultr":
        raise providers.ProviderError("این عملیات فقط برای سرورهای Vultr است")
    server = await providers.Provider(acc).server(srv_id)
    return acc, server


@dp.callback_query(F.data.startswith("v4add:"))
async def vultr_add_ipv4_prompt(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    try:
        _, server = await _vultr_action_context(acc_id, srv_id)
    except Exception as e:
        await cb.answer(str(e)[:180], show_alert=True)
        return
    b = InlineKeyboardBuilder()
    b.button(text="⚠️ بله، IPv4 جدید اضافه کن", callback_data=f"v4add_ok:{acc_id}:{srv_id}")
    b.button(text="🔙 انصراف", callback_data=f"srv:{acc_id}:{srv_id}")
    b.adjust(1)
    await cb.message.edit_text(
        "⚠️ <b>افزودن IPv4 جدید</b>\n\n"
        f"برای <b>{html.escape(str(server['label']))}</b> یک IPv4 عمومی دیگر می‌سازد و سرور را ریبوت می‌کند.\n"
        "آی‌پی اصلی Vultr جایگزین نمی‌شود؛ آی‌پی جدید به سرور اضافه خواهد شد.",
        reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("v4add_ok:"))
async def vultr_add_ipv4(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    await cb.message.edit_text("⏳ در حال ساخت IPv4 و ریبوت سرور…")
    try:
        acc, _ = await _vultr_action_context(acc_id, srv_id)
        result = await providers.Provider(acc).add_vultr_ipv4(srv_id)
    except Exception as e:
        await cb.message.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:250])}</code>")
        await cb.answer()
        return
    await cb.message.edit_text(
        f"✅ IPv4 جدید درخواست شد: <code>{html.escape(str(_vultr_ip_value(result)))}</code>\n\n"
        "Vultr سرور را ریبوت می‌کند؛ چند دقیقه بعد از فهرست سرورها وضعیت را بررسی کن.",
        reply_markup=InlineKeyboardBuilder().button(
            text="🔙 سرور", callback_data=f"srv:{acc_id}:{srv_id}").as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("float:"))
async def vultr_floating_ip_prompt(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    try:
        _, server = await _vultr_action_context(acc_id, srv_id)
    except Exception as e:
        await cb.answer(str(e)[:180], show_alert=True)
        return
    b = InlineKeyboardBuilder()
    b.button(text="⚠️ بله، Floating IP بساز", callback_data=f"float_ok:{acc_id}:{srv_id}")
    b.button(text="🔙 انصراف", callback_data=f"srv:{acc_id}:{srv_id}")
    b.adjust(1)
    await cb.message.edit_text(
        "⚠️ <b>افزودن Floating IP</b>\n\n"
        f"یک Reserved IPv4 جدید در منطقهٔ <code>{html.escape(str(server['region']))}</code> می‌سازد و به این سرور وصل می‌کند.\n"
        "این IP جداگانه قابل جابه‌جایی بین سرورهای همان منطقه است و ممکن است هزینهٔ Vultr داشته باشد.",
        reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("float_ok:"))
async def vultr_floating_ip(cb: CallbackQuery):
    _, acc_id, srv_id = cb.data.split(":")
    await cb.message.edit_text("⏳ در حال ساخت و اتصال Floating IP…")
    try:
        acc, server = await _vultr_action_context(acc_id, srv_id)
        reserved = await providers.Provider(acc).create_and_attach_vultr_floating_ip(
            srv_id, server["region"], f"cloudbot-{server['label']}")
    except Exception as e:
        await cb.message.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:250])}</code>")
        await cb.answer()
        return
    await cb.message.edit_text(
        f"✅ Floating IP ساخته و متصل شد: <code>{html.escape(str(_vultr_ip_value(reserved)))}</code>\n"
        f"شناسه: <code>{html.escape(str(reserved.get('id', '—')))}</code>",
        reply_markup=InlineKeyboardBuilder().button(
            text="🔙 سرور", callback_data=f"srv:{acc_id}:{srv_id}").as_markup())
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
            server_ca=server_ca, api_key=api_key, core_config_id=core_id())
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
                                    core_config_id=core_id())
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


def kb_scan(cfg):
    b = InlineKeyboardBuilder()
    b.button(text="🖥 سرور اسکن (ایران)", callback_data="scan_srv")
    b.button(text="🌐 دامنهٔ مقصد", callback_data="scan_dom")
    b.button(text="⏱ زمان‌بندی", callback_data="scan_sched")
    auto = cfg.get("auto_apply")
    b.button(text=("✅ اعمال خودکار: روشن" if auto else "⚪️ اعمال خودکار: خاموش"),
             callback_data="scan_auto")
    b.button(text="▶️ اسکن الان", callback_data="scan_now")
    b.button(text="📊 وضعیت", callback_data="scan_status")
    b.button(text="📋 آی‌پی‌های پیدا شده", callback_data="scan_found")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(2, 2, 2, 1, 1)
    return b.as_markup()


def _scan_summary(cfg):
    ssh = cfg.get("ssh") or {}
    dom = cfg.get("fqdn") or "—"
    iv = cfg.get("interval_hours")
    return (
        "🔎 <b>اسکنر آی‌پی تمیز کلادفلر</b>\n\n"
        f"🖥 سرور اسکن: <code>{ssh.get('host','—')}</code>\n"
        f"🌐 دامنهٔ مقصد: <code>{html.escape(str(dom))}</code>\n"
        f"⏱ هر: <b>{str(iv)+' ساعت' if iv else 'دستی'}</b>\n"
        f"♻️ اعمال خودکار: <b>{'روشن' if cfg.get('auto_apply') else 'خاموش'}</b>\n"
        f"⭐️ بهترین فعلی: <code>{cfg.get('last_best_ip') or '—'}</code>")


@dp.callback_query(F.data == "scan")
async def cb_scan(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    cfg = st.cfscan()
    await cb.message.edit_text(_scan_summary(cfg), reply_markup=kb_scan(cfg))
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
        await msg.answer("❌ قالب نادرست. host:port:user:password", reply_markup=kb_scan(st.cfscan()))
        return
    cfg = st.update_cfscan(ssh=s)
    await msg.answer("✅ سرور اسکن ذخیره شد.", reply_markup=kb_scan(cfg))


@dp.callback_query(F.data == "scan_dom")
async def scan_dom(cb: CallbackQuery, state: FSMContext):
    token = st.cf_token()
    if not token:
        await cb.answer("اول توکن کلادفلر را در بخش «DNS کلادفلر» تنظیم کن.", show_alert=True)
        return
    await cb.message.edit_text("در حال گرفتن دامنه‌ها…")
    try:
        zones = await Cloudflare(token).zones()
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_scan(st.cfscan()))
        await cb.answer()
        return
    await state.update_data(zones=zones)
    b = InlineKeyboardBuilder()
    for i, (_zid, name) in enumerate(zones):
        b.button(text=name, callback_data=f"scanz:{i}")
    b.button(text="🔙 انصراف", callback_data="scan")
    b.adjust(1)
    await cb.message.edit_text("دامنه‌ای که آی‌پی تمیز پشتش برود را انتخاب کن:",
                               reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("scanz:"))
async def scan_pick_zone(cb: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    zid, zname = data["zones"][int(cb.data.split(":")[1])]
    await state.update_data(zone_id=zid, zone_name=zname)
    await state.set_state(Scan.subdomain)
    await cb.message.edit_text(
        f"دامنه: <b>{html.escape(zname)}</b>\n\n"
        f"نام ساب‌دامین را بفرست (مثلاً <code>cf</code>). برای خودِ دامنه <code>@</code>.")
    await cb.answer()


@dp.message(Scan.subdomain)
async def scan_sub_set(msg: Message, state: FSMContext):
    sub = msg.text.strip().lower()
    data = await state.get_data()
    await state.clear()
    fqdn = data["zone_name"] if sub == "@" else f"{sub}.{data['zone_name']}"
    cfg = st.update_cfscan(zone_id=data["zone_id"], zone_name=data["zone_name"], fqdn=fqdn)
    await msg.answer(f"✅ دامنهٔ مقصد: <code>{html.escape(fqdn)}</code>", reply_markup=kb_scan(cfg))


@dp.callback_query(F.data == "scan_sched")
async def scan_sched(cb: CallbackQuery, state: FSMContext):
    b = InlineKeyboardBuilder()
    for h in (1, 3, 6, 12, 24):
        b.button(text=f"هر {h} ساعت", callback_data=f"scaniv:{h}")
    b.button(text="✏️ دلخواه", callback_data="scaniv_custom")
    b.button(text="⛔️ دستی (بدون زمان‌بندی)", callback_data="scaniv:0")
    b.button(text="🔙 بازگشت", callback_data="scan")
    b.adjust(3, 2, 1, 1)
    await cb.message.edit_text("هر چند ساعت یک‌بار اسکن شود؟", reply_markup=b.as_markup())
    await cb.answer()


@dp.callback_query(F.data.startswith("scaniv:"))
async def scan_iv_set(cb: CallbackQuery):
    h = int(cb.data.split(":")[1])
    cfg = st.update_cfscan(interval_hours=(h or None))
    await cb.message.edit_text(_scan_summary(cfg), reply_markup=kb_scan(cfg))
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
        await msg.answer("❌ عدد معتبر بفرست.", reply_markup=kb_scan(st.cfscan()))
        return
    cfg = st.update_cfscan(interval_hours=h)
    await msg.answer(f"✅ هر {h} ساعت.", reply_markup=kb_scan(cfg))


@dp.callback_query(F.data == "scan_auto")
async def scan_auto(cb: CallbackQuery):
    cfg = st.cfscan()
    cfg = st.update_cfscan(auto_apply=not cfg.get("auto_apply"))
    await cb.message.edit_text(_scan_summary(cfg), reply_markup=kb_scan(cfg))
    await cb.answer("اعمال خودکار " + ("روشن" if cfg.get("auto_apply") else "خاموش"))


@dp.callback_query(F.data == "scan_status")
async def scan_status(cb: CallbackQuery):
    cfg = st.cfscan()
    ts = cfg.get("last_scan_ts")
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "هرگز"
    txt = (_scan_summary(cfg) + f"\n\n🕐 آخرین اسکن: <b>{when}</b>")
    if cfg.get("last_best"):
        txt += f"\n📈 معیار بهترین: {_fmt_metrics(cfg['last_best'])}"
    await cb.message.edit_text(txt, reply_markup=kb_scan(cfg))
    await cb.answer()


@dp.callback_query(F.data == "scan_found")
async def scan_found(cb: CallbackQuery):
    found = st.found_ips()
    if not found:
        await cb.answer("هنوز آی‌پی‌ای ثبت نشده.", show_alert=True)
        return
    lines = ["📋 <b>آخرین آی‌پی‌های تمیز پیدا شده</b>", ""]
    for e in found[:12]:
        when = time.strftime("%m-%d %H:%M", time.localtime(e.get("ts", 0)))
        applied = " ✅اعمال شد" if e.get("applied") else ""
        lines.append(f"<code>{e.get('ip')}</code> — {_fmt_metrics(e)}{applied}  <i>{when}</i>")
    b = InlineKeyboardBuilder()
    b.button(text="🔙 بازگشت", callback_data="scan")
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


async def _do_scan(log, *, apply_if_better):
    """Run one scan; return (best, applied, message)."""
    cfg = st.cfscan()
    ssh = cfg.get("ssh")
    if not ssh:
        raise RuntimeError("سرور اسکن تنظیم نشده")
    results, tail = await cfscanner.run_scan(ssh, st.jump(), log)
    if not results:
        raise RuntimeError("اسکن نتیجه‌ای نداشت")
    best = results[0]
    prev = cfg.get("last_best")
    better = cfscanner.is_better(best, cfg.get("last_best_ip"), prev)
    st.update_cfscan(last_scan_ts=int(time.time()), last_best_ip=best["ip"], last_best=best)

    applied = False
    fqdn = cfg.get("fqdn")
    if apply_if_better and fqdn and st.cf_token():
        # Decide against what is ACTUALLY on the domain, not against the last
        # scan's best - otherwise a stale or manually-set record never gets
        # corrected. Replace the record when its IP has dropped out of the
        # clean set entirely, or when the best beats it by a real margin;
        # leave it alone when it is still fine, to avoid hourly flip-flopping.
        try:
            cf = Cloudflare(st.cf_token())
            zone = await cf.zone_for(fqdn)
            rec = await cf.find_a_record(zone[0], fqdn) if zone else None
            cur_ip = rec["content"] if rec else None
            cur_metrics = next((r for r in results if r["ip"] == cur_ip), None)
            if cur_ip != best["ip"] and (
                cur_ip is None or cur_metrics is None
                or cfscanner.is_better(best, cur_ip, cur_metrics)
            ):
                if rec:
                    await cf.update_a(zone[0], rec, best["ip"])
                else:
                    await cf.create_a(zone[0], fqdn, best["ip"], proxied=False)
                applied = True
        except Exception as e:
            await log(f"⚠️ اعمال روی دامنه خطا داد: {html.escape(str(e)[:150])}")
    if better or applied:
        st.add_found_ip({**best, "applied": applied})
    return best, better, applied


@dp.callback_query(F.data == "scan_now")
async def scan_now(cb: CallbackQuery):
    cfg = st.cfscan()
    if not cfg.get("ssh"):
        await cb.answer("اول سرور اسکن را تنظیم کن.", show_alert=True)
        return
    await cb.answer()
    status = await cb.message.edit_text("🔎 شروع اسکن…")
    lines = ["🔎 <b>اسکن آی‌پی تمیز</b>", ""]

    async def logline(t):
        lines.append(t)
        try:
            await status.edit_text("\n".join(lines[-12:]))
        except Exception:
            pass

    try:
        best, better, applied = await _do_scan(logline, apply_if_better=cfg.get("auto_apply"))
        tag = ("🎉 بهتر از قبلی" if better else "بدون بهبود نسبت به فعلی")
        extra = ""
        if not applied and cfg.get("fqdn"):
            extra = "\n\nبرای گذاشتنش پشت دامنه از دکمهٔ زیر، یا «اعمال خودکار» را روشن کن."
        b = InlineKeyboardBuilder()
        if not applied and cfg.get("fqdn"):
            b.button(text=f"🌐 بگذار پشت {cfg['fqdn']}", callback_data="scan_apply_last")
        b.button(text="🔙 منوی اسکنر", callback_data="scan")
        b.adjust(1)
        await status.edit_text(
            f"✅ <b>اسکن تمام شد</b> — {tag}\n\n"
            f"⭐️ بهترین: <code>{best['ip']}</code>\n{_fmt_metrics(best)}"
            + (f"\n✅ روی <code>{cfg['fqdn']}</code> اعمال شد" if applied else "") + extra,
            reply_markup=b.as_markup())
    except Exception as e:
        log.exception("scan_now failed")
        await status.edit_text(f"❌ خطا: <code>{html.escape(str(e)[:300])}</code>",
                               reply_markup=kb_scan(cfg))


@dp.callback_query(F.data == "scan_apply_last")
async def scan_apply_last(cb: CallbackQuery):
    cfg = st.cfscan()
    ip = cfg.get("last_best_ip")
    fqdn = cfg.get("fqdn")
    if not (ip and fqdn):
        await cb.answer("آی‌پی یا دامنه تنظیم نشده.", show_alert=True)
        return
    await cb.answer()
    try:
        await _apply_ip(fqdn, ip)
        await cb.message.edit_text(f"✅ <code>{fqdn}</code> → <code>{ip}</code>",
                                   reply_markup=kb_scan(cfg))
    except Exception as e:
        await cb.message.edit_text(f"❌ {html.escape(str(e)[:200])}", reply_markup=kb_scan(cfg))


async def scan_scheduler():
    """Run the scan on the configured interval and alert on a better IP."""
    await asyncio.sleep(20)
    while True:
        try:
            cfg = st.cfscan()
            iv = cfg.get("interval_hours")
            if iv and cfg.get("ssh"):
                due = (time.time() - (cfg.get("last_scan_ts") or 0)) >= iv * 3600
                if due:
                    async def qlog(t):
                        log.info("scan: %s", t)
                    best, better, applied = await _do_scan(qlog, apply_if_better=cfg.get("auto_apply"))
                    if better or applied:
                        head = ("🎉 <b>آی‌پی تمیزتر پیدا شد</b>" if better
                                else "🔄 <b>آی‌پی دامنه به‌روزرسانی شد</b>")
                        msg = f"{head}\n\n⭐️ <code>{best['ip']}</code>\n{_fmt_metrics(best)}"
                        if applied and cfg.get("fqdn"):
                            msg += f"\n\n✅ روی <code>{cfg['fqdn']}</code> اعمال شد."
                        elif cfg.get("fqdn"):
                            msg += (f"\n\nبرای گذاشتنش پشت <code>{cfg['fqdn']}</code> "
                                    f"«اعمال خودکار» را روشن کن.")
                        try:
                            await bot.send_message(OWNER, msg)
                        except Exception:
                            log.exception("scan alert delivery failed")
        except Exception:
            log.exception("scan scheduler pass failed")
        await asyncio.sleep(300)


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
        "<code>سرور اول | node1.example.com | 443 | tls</code>\n"
        "<code>اوپن‌وی‌پی‌ان | 203.0.113.10 | 1194 | notls</code>\n\n"
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


async def _repair_one_tunnel(rec, acc, fsrv, banned, jump, log_fn):
    """The retry ladder for a single tunnel. Returns (ok, description)."""
    kind = rec["kind"]
    other = tunnelwatch.OTHER_KIND[kind]

    # A live account usually just needs the tunnel stood back up, and the
    # transport swap costs nothing but a rebuild - so both come before paying
    # for a new server.
    if not banned:
        await log_fn(f"تلاش ۱: برپاسازی دوبارهٔ {kind} روی همان سرور")
        ok, _tid = await tunnelwatch.rebuild(st, rec, jump=jump, log=log_fn)
        if ok:
            return True, f"{kind} دوباره برپا شد"
        rec = st.tunnel(rec["id"]) or rec

        await log_fn(f"تلاش ۲: تعویض نوع تانل به {other}")
        ok, tid = await tunnelwatch.rebuild(st, rec, kind=other, jump=jump, log=log_fn)
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

    for attempt in (1, 2):
        await log_fn(f"ساخت سرور خارجی تازه (تلاش {attempt}/2)…")
        foreign, srv = await tunnelwatch.new_foreign_server(
            st, target_acc, fsrv, log_fn)
        for k in (kind, other):
            ok, _tid = await tunnelwatch.rebuild(
                st, rec, kind=k, foreign=foreign, jump=jump, log=log_fn)
            if ok:
                # The old endpoint is only scrapped once its replacement works.
                if not banned:
                    try:
                        await providers.Provider(acc).delete_server(fsrv["id"])
                        st.forget_server(acc["id"], fsrv["id"])
                    except Exception as e:
                        await log_fn(f"⚠️ حذف سرور قدیمی نشد: {str(e)[:120]}")
                return True, (f"سرور خارجی جدید <code>{foreign['host']}</code> "
                              f"با تانل {k}")
            rec = st.tunnel(rec["id"]) or rec
        await log_fn("این آی‌پی جواب نداد؛ حذف و گرفتن آی‌پی دیگر…")
        await replacer.scrap(st, target_acc, srv, log_fn)
    return False, "با دو آی‌پی تازه و هر دو نوع تانل هم بالا نیامد"


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
                         api_key=api_key, core_config_id=core_id())
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
                await bot.send_message(
                    OWNER, f"❌ <b>تعمیر تانل {name} نشد</b>\n"
                           f"<code>{html.escape(str(e)[:300])}</code>")
                continue
            lines = []
            if info.get("note"):
                lines.append(info["note"])
            good = sum(1 for r in info["results"] if r["ok"])
            lines.append(f"{'✅' if good == len(info['results']) else '⚠️'} "
                         f"<b>تعمیر تانل</b> — {good} از {len(info['results'])} برگشت")
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
                    await _do_watch(alert=True)
        except Exception:
            log.exception("watchdog pass failed")
        await asyncio.sleep(60)



# ==========================================================================
# settings: everything an installation needs, entered from Telegram
# ==========================================================================
class PanelCfg(StatesGroup):
    url = State()
    user = State()
    password = State()
    core = State()


def kb_settings():
    c = panel_cfg()
    j = st.jump()
    b = InlineKeyboardBuilder()
    b.button(text=("🎛 پنل: " + (c.get("url") or "تنظیم نشده")), callback_data="set_panel")
    b.button(text=("🇮🇷 واسط ایران: " + (j.get("host") if j else "تنظیم نشده")),
             callback_data="set_jump")
    b.button(text=("🌐 توکن کلادفلر: " + ("ثبت شده" if st.cf_token() else "تنظیم نشده")),
             callback_data="cf_token_set")
    b.button(text="🔙 بازگشت", callback_data="home")
    b.adjust(1)
    return b.as_markup()


@dp.callback_query(F.data == "settings")
async def cb_settings(cb: CallbackQuery):
    await cb.answer()
    c = panel_cfg()
    await cb.message.edit_text(
        "⚙️ <b>تنظیمات</b>\n\n"
        "هر چیزی که این ربات برای کار کردن لازم دارد از همین‌جا تنظیم می‌شود؛ "
        "هیچ‌کدام داخل کد یا ایمیج نیست.\n\n"
        f"🎛 پنل: <code>{html.escape(c.get('url') or '—')}</code>\n"
        f"🔢 هستهٔ نودها: <code>{c.get('core_id') or 'خودکار'}</code>",
        reply_markup=kb_settings())


@dp.callback_query(F.data == "set_panel")
async def set_panel(cb: CallbackQuery, state: FSMContext):
    await cb.answer()
    await state.set_state(PanelCfg.url)
    await cb.message.answer(
        "🎛 <b>اتصال به پنل</b>\n\n"
        "۱/۴ — آدرس پنل را بفرست، با پروتکل و پورت:\n"
        "<code>https://panel.example.com:8000</code>\n\n/cancel برای انصراف")


@dp.message(PanelCfg.url)
async def panel_url(msg: Message, state: FSMContext):
    u = msg.text.strip().rstrip("/")
    if not u.startswith("http"):
        await msg.answer("با http:// یا https:// شروع کن.")
        return
    await state.update_data(url=u)
    await state.set_state(PanelCfg.user)
    await msg.answer("۲/۴ — نام کاربری ادمین پنل؟")


@dp.message(PanelCfg.user)
async def panel_user(msg: Message, state: FSMContext):
    await state.update_data(user=msg.text.strip())
    await state.set_state(PanelCfg.password)
    await msg.answer("۳/۴ — رمز ادمین پنل؟\n<i>پیام رمز پاک می‌شود.</i>")


@dp.message(PanelCfg.password)
async def panel_password(msg: Message, state: FSMContext):
    await state.update_data(password=msg.text)
    try:
        await msg.delete()
    except Exception:
        pass
    await state.set_state(PanelCfg.core)
    await msg.answer(
        "۴/۴ — شناسهٔ هسته‌ای که نودهای تازه به آن وصل شوند.\n"
        "اگر نمی‌دانی <code>0</code> بفرست تا پنل خودش تصمیم بگیرد.")


@dp.message(PanelCfg.core)
async def panel_core(msg: Message, state: FSMContext):
    raw = msg.text.strip()
    if not raw.isdigit():
        await msg.answer("یک عدد بفرست (یا 0).")
        return
    d = await state.get_data()
    await state.clear()
    note = await msg.answer("در حال تست اتصال به پنل…")
    try:
        p = Panel(d["url"], d["user"], d["password"])
        nodes = await p.list_nodes()
    except Exception as e:
        await note.edit_text(
            f"❌ وصل نشد: <code>{html.escape(str(e)[:250])}</code>\n\n"
            "آدرس، نام کاربری و رمز را چک کن و دوباره از «⚙️ تنظیمات» امتحان کن.")
        return
    st.set_panel(d["url"], d["user"], d["password"], raw)
    await note.edit_text(
        f"✅ پنل وصل شد — {len(nodes)} نود دیده شد.\n"
        f"هستهٔ نودهای تازه: <code>{raw if raw != '0' else 'خودکار'}</code>",
        reply_markup=kb_settings())


async def main():
    asyncio.create_task(scan_scheduler())
    asyncio.create_task(watch_scheduler())
    asyncio.create_task(pending_scheduler())
    # Seed the panel from the environment on first run only, so an installer
    # can prefill it while the bot stays configurable from Telegram afterwards.
    if not st.panel().get("url") and PANEL_SEED["url"]:
        st.set_panel(PANEL_SEED["url"], PANEL_SEED["user"],
                     PANEL_SEED["password"], PANEL_SEED["core_id"] or 0)
        log.info("panel seeded from environment: %s", PANEL_SEED["url"])
    # Seed the Iran jump host once, from the env, if not already stored.
    if not st.jump() and os.environ.get("CLOUDBOT_JUMP"):
        h, p, u, pw = os.environ["CLOUDBOT_JUMP"].split(":", 3)
        st.set_jump(h, int(p), u, pw)
        log.info("iran jump host seeded: %s", h)
    log.info("cloudbot up, owner=%s panel=%s core=%s", OWNER,
             panel_cfg().get("url") or "(not configured)", core_id())
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
