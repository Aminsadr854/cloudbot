"""Owner-only Telegram menus for provider formats and session pools."""
import html
import secrets
from functools import wraps

from aiogram import F
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery
from aiogram.utils.keyboard import InlineKeyboardBuilder

from proxy_pool import ProxyPoolError, import_format, resolve_country, session_ids


class Pool(StatesGroup):
    label = State()
    format = State()
    ids = State()
    family = State()
    rename = State()
    more_ids = State()
    edit_format = State()
    availability = State()
    country = State()
    validation = State()


def register_proxy_ui(dp, host):
    st = host['st']

    def owner(fn):
        @wraps(fn)
        async def guarded(event, state):
            if event.from_user.id != host['OWNER']:
                if isinstance(event, CallbackQuery):
                    await event.answer('این ربات خصوصی است.', show_alert=True)
                else:
                    await event.answer('این ربات خصوصی است.')
                return
            return await fn(event, state)
        return guarded

    def menu():
        b = InlineKeyboardBuilder()
        default = st.get('proxy_default')
        for p in st.proxy_providers():
            mark = '⭐ ' if str(p['id']) == default else ''
            status = '' if p['enabled'] else ' · غیرفعال'
            b.button(text=f"{mark}{p['label']}{status}", callback_data=f"pp:{p['id']}:show")
        b.button(text='➕ افزودن ارائه‌دهنده پراکسی', callback_data='pp:add')
        b.button(text='🔙 بازگشت', callback_data='home')
        b.adjust(1)
        return b.as_markup()

    def provider_card(pid, note=''):
        p = st.proxy_provider(pid)
        if not p:
            return 'ارائه‌دهنده یافت نشد.', menu()
        sessions = st.proxy_sessions(pid)
        t = p['template']
        lines = [f"🌐 <b>{html.escape(p['label'])}</b>",
                 f"میزبان: <code>{html.escape(t['host'])}:{t['port']}</code>",
                 f"نوع: {t['scheme']}",
                 f"شناسه‌ها: {len(sessions)} · فعال: {sum(s['enabled'] for s in sessions)}",
                 '🔐 قالب و رمز عبور رمزنگاری شده‌اند.', '', 'اتصال اکانت‌ها:']
        for acc in st.accounts():
            binding = st.proxy_binding(acc['id'])
            if binding and binding['provider_id'] == pid:
                lines.append(f"• #{acc['id']} {html.escape(acc['label'][:64])}: "
                             f"{binding['country']} · <code>{html.escape(binding['session_id'])}</code>")
        if lines[-1] == 'اتصال اکانت‌ها:':
            lines.append('بدون اتصال')
        # Paginated IDs and bounded account display keep Telegram below 4096.
        if len(lines) > 19:
            lines = lines[:19] + ['… اتصال‌های بیشتر در منوی اکانت‌ها']
        if note:
            lines.append('\n' + html.escape(note))
        b = InlineKeyboardBuilder()
        for action, label in [('default', '⭐ پیش‌فرض'), ('rename', '✏️ تغییر نام'),
                              ('ids', '➕ افزودن شناسه‌ها'), ('sessions', '📋 مدیریت شناسه‌ها'),
                              ('availability', '🌍 ظرفیت یک کشور'),
                              ('format', '✏️ قالب بدون اتصال'),
                              ('toggle', '⏸ غیرفعال / فعال'), ('delete', '🗑 حذف بدون اتصال')]:
            b.button(text=label, callback_data=f'pp:{pid}:{action}')
        b.button(text='🔙 ارائه‌دهندگان', callback_data='proxy_pools')
        b.adjust(2, 2, 1, 1, 1, 1)
        return '\n'.join(lines), b.as_markup()

    def choices(target):
        b = InlineKeyboardBuilder()
        for p in st.proxy_providers():
            if p['enabled']:
                b.button(text=p['label'], callback_data=f"poolprovider:{target}:{p['id']}")
        b.button(text='➕ افزودن ارائه‌دهنده', callback_data=f'pooladd:{target}')
        b.button(text='✍️ پراکسی سفارشی', callback_data=f'poolcustom:{target}')
        if target != 'new':
            b.button(text='🔙 اکانت', callback_data=f'acc:{target}')
        b.adjust(1)
        return b.as_markup()

    def assignment_markup(target):
        b = InlineKeyboardBuilder()
        b.button(text='🔀 انتخاب ارائه‌دهنده', callback_data=f'poolpick:{target}')
        b.button(text='✍️ پراکسی سفارشی', callback_data=f'poolcustom:{target}')
        b.button(text='➕ مدیریت شناسه‌ها', callback_data='proxy_pools')
        b.button(text='🔙 لغو', callback_data='home' if target == 'new' else f'acc:{target}')
        b.adjust(1)
        return b.as_markup()

    @dp.callback_query(F.data == 'proxy_pools')
    @owner
    async def show_pools(cb, state):
        await host['clear_proxy_state'](state)
        conflicts = st.proxy_conflicts()
        text = '🌐 <b>ارائه‌دهندگان پراکسی</b>\nقالب و شناسه‌ها را یک بار اضافه کن؛ سپس برای اکانت فقط کشور را بفرست.'
        if conflicts:
            text += '\n\n⚠️ پراکسی مشترک در اکانت‌های زیر وجود دارد؛ یکی را تغییر بده:'
            for owners in conflicts[:10]:
                text += '\n' + ', '.join(f"#{a['id']} {html.escape(a['label'][:40])}" for a in owners[:8])
        await cb.message.edit_text(text, reply_markup=menu())
        await cb.answer()

    @dp.callback_query(F.data.startswith('pooladd:'))
    @dp.callback_query(F.data == 'pp:add')
    @owner
    async def add_start(cb, state):
        if cb.data.startswith('pooladd:'):
            target = cb.data.split(':', 1)[1]
            data = await state.get_data()
            if data.get('pool_target') != target:
                await cb.answer('درخواست قدیمی است.', show_alert=True)
                return
            if data.get('proxy_request'):
                st.release_proxy_reservation(data['proxy_request'])
            await state.update_data(proxy_request=None, pool_return=target, add_request_id=secrets.token_urlsafe(16))
        else:
            await host['clear_proxy_state'](state)
        await state.set_state(Pool.label)
        await cb.message.edit_text('نام دلخواه برای ارائه‌دهنده پراکسی را بفرست.')
        await cb.answer()

    @dp.message(Pool.label)
    @owner
    async def label(msg, state):
        value = (msg.text or '').strip()
        if not value or len(value) > 64:
            await msg.answer('نام باید بین ۱ و ۶۴ کاراکتر باشد.')
            return
        await state.update_data(pool_label=value)
        await state.set_state(Pool.format)
        await msg.answer('خطوط کامل پراکسی را بفرست، یا یک قالب مثل:\n'
                         '<code>host:port:login-{country}-sid-{session_id}:password</code>\n'
                         'قالب هر ارائه‌دهنده‌ای مجاز است؛ نام کاربری را مطابق سرویس خودت تنظیم کن.\n'
                         '<code>{country}</code> با کد دوحرفی بزرگ کشور (DE، US، SG) و '
                         '<code>{session_id}</code> با شناسه سشن جایگزین می‌شود. '
                         'این دو جای‌نگهدار را دقیقاً یک بار در نام کاربری بنویس. '
                         'سپس چند شناسه سشن را یکی در هر خط اضافه کن. پیام حاوی رمز پاک می‌شود.')

    @dp.message(Pool.format)
    @owner
    async def format_input(msg, state):
        try:
            template, ids = import_format(msg.text or '')
        except ProxyPoolError as exc:
            await msg.answer(html.escape(str(exc)))
            return
        finally:
            try:
                await msg.delete()
            except Exception:
                pass
        await state.update_data(pool_template=template, pool_ids=ids)
        if ids:
            await save_provider(msg.answer, state)
        else:
            await state.set_state(Pool.ids)
            await msg.answer('شناسه‌های سشن را یکی در هر خط بفرست؛ حروف بزرگ/کوچک و صفرهای اول حفظ می‌شوند.')

    @dp.message(Pool.ids)
    @owner
    async def ids_input(msg, state):
        try:
            ids = session_ids(msg.text or '')
        except ProxyPoolError as exc:
            await msg.answer(html.escape(str(exc)))
            return
        await state.update_data(pool_ids=ids)
        await save_provider(msg.answer, state)

    async def save_provider(answer, state):
        data = await state.get_data()
        try:
            pid = st.add_proxy_provider(data['pool_label'], data['pool_template'], data['pool_ids'], 'default')
        except ProxyPoolError as exc:
            await answer(html.escape(str(exc)))
            return
        target = data.get('pool_return')
        if target:
            await state.update_data(pool_return=None, pool_provider_id=pid, pool_target=target, pool_another=False)
            await state.set_state(Pool.country)
            await answer('✅ ارائه‌دهنده ذخیره شد. کشور را بفرست (مثلاً DE، US یا آلمان).',
                         reply_markup=assignment_markup(target))
        else:
            await host['clear_proxy_state'](state)
            text, markup = provider_card(pid, '✅ ارائه‌دهنده ذخیره شد.')
            await answer(text, reply_markup=markup)

    @dp.callback_query(Pool.family, F.data.startswith('poolfamily:'))
    @owner
    async def finish_provider(cb, state):
        await cb.answer()
        await save_provider(cb.message.edit_text, state)

    @dp.callback_query(F.data.startswith('pp:'))
    @owner
    async def provider_action(cb, state):
        _, raw_pid, action = cb.data.split(':')
        pid = int(raw_pid)
        await host['clear_proxy_state'](state)
        if action in {'rename', 'ids', 'availability', 'format'}:
            await state.update_data(pool_provider_id=pid)
            await state.set_state({'rename': Pool.rename, 'ids': Pool.more_ids, 'availability': Pool.availability, 'format': Pool.edit_format}[action])
            await cb.message.edit_text({'rename': 'نام تازه را بفرست.', 'ids': 'شناسه‌ها را یکی در هر خط بفرست.',
                                        'availability': 'نام کشور یا کد دوحرفی را بفرست.',
                                        'format': 'قالب تازه یا یک خط پراکسی را بفرست. فقط قالب بدون اتصال قابل ویرایش است؛ پیام پاک می‌شود.'}[action])
        elif action == 'sessions':
            await session_page(cb, pid, 0)
        else:
            try:
                if action != 'show':
                    st.manage_proxy_provider(pid, action)
            except ProxyPoolError as exc:
                await cb.answer(str(exc), show_alert=True)
                return
            if action == 'delete':
                await cb.message.edit_text('✅ حذف شد.', reply_markup=menu())
            else:
                text, markup = provider_card(pid)
                await host['edit_menu_message'](cb.message, text, reply_markup=markup)
        await cb.answer()

    @dp.message(Pool.rename)
    @dp.message(Pool.more_ids)
    @dp.message(Pool.availability)
    @dp.message(Pool.edit_format)
    @owner
    async def provider_input(msg, state):
        data, current = await state.get_data(), await state.get_state()
        pid = data['pool_provider_id']
        try:
            if current == Pool.rename.state:
                if len((msg.text or '').strip()) > 64:
                    raise ProxyPoolError('نام حداکثر ۶۴ کاراکتر است.')
                st.manage_proxy_provider(pid, 'rename', msg.text)
                note = '✅ نام ذخیره شد.'
            elif current == Pool.more_ids.state:
                count = st.add_proxy_sessions(pid, session_ids(msg.text or ''))
                note = f'✅ {count} شناسه تازه اضافه شد؛ موارد تکراری نادیده گرفته شدند.'
            elif current == Pool.edit_format.state:
                try:
                    template, _ = import_format(msg.text or '')
                    st.manage_proxy_provider(pid, 'format', template)
                finally:
                    try:
                        await msg.delete()
                    except Exception:
                        pass
                note = '✅ قالب ذخیره شد؛ شناسه‌های قبلی حفظ شدند.'
            else:
                country = resolve_country(msg.text)
                note = f"{country}: {st.proxy_availability(pid, country)} شناسه آزاد"
        except ProxyPoolError as exc:
            await msg.answer(html.escape(str(exc)))
            return
        await host['clear_proxy_state'](state)
        text, markup = provider_card(pid, note)
        await msg.answer(text, reply_markup=markup)

    async def session_page(cb, pid, page):
        sessions = st.proxy_sessions(pid)
        page = max(0, min(page, max(0, (len(sessions) - 1) // 8)))
        b = InlineKeyboardBuilder()
        for s in sessions[page * 8:(page + 1) * 8]:
            pos = s['id']
            b.button(text=f"{'✅' if s['enabled'] else '⏸'} {s['session_id'][:28]}",
                     callback_data=f'ps:{pid}:{pos}:toggle:{page}')
            b.button(text='🗑 حذف آزاد', callback_data=f'ps:{pid}:{pos}:delete:{page}')
        b.adjust(2)
        if page:
            b.row(host['InlineKeyboardButton'](text='◀️', callback_data=f'ps:{pid}:0:page:{page-1}'))
        if (page + 1) * 8 < len(sessions):
            b.row(host['InlineKeyboardButton'](text='▶️', callback_data=f'ps:{pid}:0:page:{page+1}'))
        b.row(host['InlineKeyboardButton'](text='🔙 ارائه‌دهنده', callback_data=f'pp:{pid}:show'))
        await host['edit_menu_message'](cb.message, f'📋 شناسه‌ها · صفحه {page + 1}\nغیرفعال‌کردن، اتصال فعلی را حفظ می‌کند.', reply_markup=b.as_markup())

    @dp.callback_query(F.data.startswith('ps:'))
    @owner
    async def session_action(cb, state):
        _, pid, pos, action, page = cb.data.split(':')
        pid, pos, page = int(pid), int(pos), int(page)
        try:
            if action != 'page':
                s = next((s for s in st.proxy_sessions(pid) if s['id'] == pos), None)
                if not s:
                    raise ProxyPoolError('شناسه یافت نشد.')
                st.manage_proxy_session(pid, s['session_id'], action)
            await session_page(cb, pid, page)
        except ProxyPoolError as exc:
            await cb.answer(str(exc), show_alert=True)
            return
        await cb.answer()

    async def enter_country(cb, state, target, pid, another=False):
        p = st.proxy_provider(pid)
        await state.set_state(Pool.country)
        if not p or not p['enabled']:
            await state.update_data(pool_provider_id=None)
            await cb.message.edit_text('ارائه‌دهنده فعال را انتخاب کن:', reply_markup=choices(target))
            return
        await state.update_data(pool_target=target, pool_provider_id=pid, pool_another=another)
        await cb.message.edit_text(f"🌍 کشور پراکسی برای <b>{html.escape(p['label'])}</b> را بفرست "
                                   '(مثلاً Germany، آلمان یا DE).', reply_markup=assignment_markup(target))

    @dp.callback_query(F.data.startswith('pooluse:'))
    @dp.callback_query(F.data.startswith('poolpick:'))
    @dp.callback_query(F.data.startswith('poolanother:'))
    @owner
    async def assign_start(cb, state):
        action, target = cb.data.split(':')
        data = await state.get_data()
        if target == 'new':
            if 'token' not in data or 'label' not in data:
                await cb.answer('ابتدا افزودن اکانت را شروع کن.', show_alert=True)
                return
            if data.get('proxy_request'):
                st.release_proxy_reservation(data['proxy_request'])
            await state.update_data(proxy_request=None, add_request_id=secrets.token_urlsafe(16))
        else:
            origin = data.get('proxy_origin', 'account') if data.get('acc_id') == int(target) else 'account'
            await host['clear_proxy_state'](state)
            await state.update_data(acc_id=int(target), proxy_origin=origin)
            if not st.account(int(target)):
                await cb.answer('اکانت یافت نشد.', show_alert=True)
                return
        await state.update_data(pool_target=target)
        binding = st.proxy_binding(int(target)) if target != 'new' else None
        pid = binding['provider_id'] if binding else int(st.get('proxy_default') or 0)
        await cb.answer()
        if action == 'poolpick' or not pid:
            await state.set_state(Pool.country)
            await cb.message.edit_text('ارائه‌دهنده پراکسی را انتخاب کن:', reply_markup=choices(target))
        elif action == 'poolanother' and binding:
            await state.update_data(pool_provider_id=pid, pool_another=True)
            await allocate_and_test(cb.message, state, binding['country'])
        else:
            await enter_country(cb, state, target, pid)

    @dp.callback_query(F.data.startswith('poolprovider:'))
    @owner
    async def choose_provider(cb, state):
        _, target, pid = cb.data.split(':')
        data = await state.get_data()
        if data.get('pool_target') != target:
            await cb.answer('درخواست قدیمی است؛ دوباره منو را باز کن.', show_alert=True)
            return
        await state.update_data(proxy_request=None)
        if data.get('proxy_request'):
            st.release_proxy_reservation(data['proxy_request'])
        await enter_country(cb, state, target, int(pid))
        await cb.answer()

    @dp.callback_query(F.data.startswith('poolcustom:'))
    @dp.callback_query(F.data == 'poolmanual')
    @owner
    async def manual(cb, state):
        data = await state.get_data()
        target = 'new' if cb.data == 'poolmanual' else cb.data.split(':', 1)[1]
        if target == 'new' and ('token' not in data or 'label' not in data):
            await cb.answer('ابتدا افزودن اکانت را شروع کن.', show_alert=True)
            return
        if target != 'new' and not st.account(int(target)):
            await cb.answer('اکانت یافت نشد.', show_alert=True)
            return
        if data.get('proxy_request'):
            st.release_proxy_reservation(data['proxy_request'])
        if target == 'new':
            await state.update_data(proxy_request=None, pool_target='new', add_request_id=secrets.token_urlsafe(16))
            await state.set_state(host['Add'].proxy)
        else:
            origin = data.get('proxy_origin', 'account')
            await host['clear_proxy_state'](state)
            await state.update_data(acc_id=int(target), proxy_origin=origin)
            await state.set_state(host['Proxy'].value)
        await cb.message.edit_text('پراکسی سفارشی را به شکل <code>host:port:username:password</code> بفرست.',
                                   reply_markup=host['kb_proxy_choice'](target))
        await cb.answer()

    @dp.message(Pool.country)
    @owner
    async def country_input(msg, state):
        progress = await msg.answer('در حال انتخاب پراکسی…')
        await allocate_and_test(progress, state, msg.text)

    async def allocate_and_test(message, state, country):
        data = await state.get_data()
        target = data.get('pool_target')
        try:
            pid = data.get('pool_provider_id')
            if not pid:
                raise ProxyPoolError('ابتدا ارائه‌دهنده را انتخاب کن.')
            result = st.allocate_proxy(pid, country, int(target) if target != 'new' else None,
                                       data.get('pool_another', False))
        except ProxyPoolError as exc:
            await message.edit_text(html.escape(str(exc)), reply_markup=assignment_markup(target))
            return
        await state.update_data(proxy=result['proxy'], proxy_request=result['token'],
                                proxy_family=result['family'], pool_country=result['country'],
                                pool_session=result['session_id'])
        await state.set_state(Pool.validation)
        await validate_pool(message, state)

    async def validate_pool(message, state, unverified=False):
        data = await state.get_data()
        data['proxy_family'] = 'default'
        target = data['pool_target']
        acc_id = int(target) if target != 'new' else None
        account = st.account(acc_id) if acc_id else data
        if not account:
            await message.edit_text('اکانت یافت نشد.')
            await host['clear_proxy_state'](state)
            return
        try:
            if not data.get('proxy_request'):
                reservation = st.reserve_proxy(data['proxy'], acc_id, data['pool_provider_id'])
                data['proxy_request'] = reservation['token']
                await state.update_data(proxy_request=reservation['token'])
            request = data['proxy_request']
            if not unverified:
                await state.update_data(pool_allow_unverified=False)
                await message.edit_text('در حال آزمایش پراکسی و مجوز API…')
                await host['providers'].Provider({**account, 'proxy': data['proxy'],
                                                  'proxy_family': data['proxy_family']}).whoami()
            # An old in-flight response must never clear or overwrite a new wizard.
            if (await state.get_data()).get('proxy_request') != request:
                st.release_proxy_reservation(request)
                return
            if acc_id:
                st.set_proxy(acc_id, data['proxy'], data['proxy_family'], proxy_request=request)
                host['menu_cache'].invalidate(acc_id)
                markup = host['kb_account_settings'](st.account(acc_id))
            else:
                acc_id = st.add_account(data['label'], data['provider'], data['token'], data['proxy'],
                                        data['proxy_family'], proxy_request=request)
                markup = host['kb_account_settings'](st.account(acc_id))
        except Exception as exc:
            request = data.get('proxy_request')
            if request:
                st.release_proxy_reservation(request)
            if (await state.get_data()).get('proxy_request') != request:
                return
            await state.update_data(proxy_request=None)
            b = InlineKeyboardBuilder()
            b.button(text='🔄 تلاش دوباره', callback_data='poolretry')
            hint = host['_proxy_failure_hint'](exc)
            if hint and account.get('provider') == 'vultr':
                await state.update_data(pool_allow_unverified=True)
                b.button(text='ذخیره بدون تأیید API', callback_data='poolunverified')
            b.button(text='✍️ پراکسی سفارشی', callback_data=f'poolcustom:{target}')
            b.button(text='🔀 تغییر ارائه‌دهنده', callback_data=f'poolpick:{target}')
            b.button(text='🌍 تغییر کشور', callback_data=f'pooluse:{target}')
            b.button(text='🔙 لغو', callback_data='home' if target == 'new' else f'acc:{target}')
            b.adjust(1)
            detail = host['safe_proxy_error'](exc, data.get('proxy'), account.get('token'))
            await message.edit_text('❌ اتصال یا تخصیص ناموفق بود؛ پراکسی قبلی حفظ شد.\n'
                                     + html.escape(detail[:300]) + hint, reply_markup=b.as_markup())
            return
        await host['clear_proxy_state'](state)
        text = f"✅ پراکسی تخصیص داده شد: {data['pool_country']} · <code>{html.escape(data['pool_session'])}</code>"
        if unverified:
            text += '\n⚠️ مجوز IP در API هنوز تأیید نشده است.'
        await message.edit_text(text, reply_markup=markup)

    @dp.callback_query(Pool.validation, F.data == 'poolretry')
    @owner
    async def retry(cb, state):
        data = await state.get_data()
        await cb.answer()
        await allocate_and_test(cb.message, state, data['pool_country'])

    @dp.callback_query(Pool.validation, F.data == 'poolunverified')
    @owner
    async def unverified(cb, state):
        if not (await state.get_data()).get('pool_allow_unverified'):
            await cb.answer('ابتدا اتصال را آزمایش کن.', show_alert=True)
            return
        await validate_pool(cb.message, state, unverified=True)
        await cb.answer()
