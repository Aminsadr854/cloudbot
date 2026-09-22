import os
import tempfile
import unittest


class AccountStoreTests(unittest.TestCase):
    def test_rename_preserves_account_settings(self):
        with tempfile.TemporaryDirectory() as d:
            old_db = os.environ.get("CLOUDBOT_DB")
            old_key = os.environ.get("CLOUDBOT_KEY")
            os.environ["CLOUDBOT_DB"] = f"{d}/cloudbot.db"
            os.environ["CLOUDBOT_KEY"] = f"{d}/secret.key"
            try:
                import store
                st = store.Store()
                acc_id = st.add_account("old", "linode", "token", "proxy:80:u:p")
                account = st.account(acc_id)
                self.assertEqual(account["label"], "old")
                self.assertEqual(account["proxy"], "proxy:80:u:p")
                st.set_proxy(acc_id, "newproxy:80:u:p")
                account = st.account(acc_id)
                self.assertEqual(account["proxy"], "newproxy:80:u:p")
            finally:
                if old_db is None:
                    os.environ.pop("CLOUDBOT_DB", None)
                else:
                    os.environ["CLOUDBOT_DB"] = old_db
                if old_key is None:
                    os.environ.pop("CLOUDBOT_KEY", None)
                else:
                    os.environ["CLOUDBOT_KEY"] = old_key
