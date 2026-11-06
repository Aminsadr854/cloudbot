import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from store import Store
from control_service import execute, InputError


class AccountEditTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = Store(str(root / 'test.db'), str(root / 'secret.key'))
        self.aid = self.store.add_account('Old name', 'linode', 'old-secret', note='memo')

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    async def test_rename_keeps_token_and_note_without_provider_request(self):
        with patch('control_service.Provider') as provider:
            result = await execute('update_account', {'account_id': self.aid, 'label': 'New name'}, self.store)
        provider.assert_not_called()
        account = self.store.account(self.aid)
        self.assertEqual((account['label'], account['token'], account['note']), ('New name', 'old-secret', 'memo'))
        self.assertNotIn('old-secret', json.dumps(result))

    async def test_verified_token_is_encrypted_and_not_returned(self):
        with patch('control_service.Provider') as provider:
            provider.return_value.account_info = AsyncMock(return_value={})
            result = await execute('update_account', {'account_id': self.aid, 'label': 'New', 'token': 'new-secret'}, self.store)
        self.assertEqual(provider.call_args.args[0]['token'], 'new-secret')
        self.assertEqual(self.store.account(self.aid)['token'], 'new-secret')
        raw = self.store.con.execute('SELECT token FROM accounts WHERE id=?', (self.aid,)).fetchone()[0]
        self.assertNotIn(b'new-secret', raw)
        self.assertNotIn('new-secret', json.dumps(result))

    async def test_failed_verification_preserves_both_fields_and_redacts_error(self):
        with patch('control_service.Provider') as provider:
            provider.return_value.account_info = AsyncMock(side_effect=Exception('invalid new-secret old-secret'))
            with self.assertRaises(InputError) as caught:
                await execute('update_account', {'account_id': self.aid, 'label': 'New', 'token': 'new-secret'}, self.store)
        self.assertNotIn('new-secret', str(caught.exception))
        self.assertNotIn('old-secret', str(caught.exception))
        account = self.store.account(self.aid)
        self.assertEqual((account['label'], account['token']), ('Old name', 'old-secret'))

    async def test_empty_name_is_rejected(self):
        with self.assertRaises(InputError):
            await execute('update_account', {'account_id': self.aid, 'label': ' '}, self.store)
