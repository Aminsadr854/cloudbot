import unittest

from aiohttp.test_utils import TestClient, TestServer

from control_api import build_app

TOKEN = "w" * 48
CONTROL = "c" * 48


class WebhookTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.sent = []
        self.markups = []

        async def send(text, markup=None):
            self.sent.append(text)
            self.markups.append(markup)

        self.send = send
        self.client = await self.make(TOKEN)

    async def make(self, webhook_token):
        client = TestClient(TestServer(build_app(
            token=CONTROL, store_factory=lambda: None,
            webhook_token=webhook_token, webhook_send=self.send)))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        return client

    def auth(self, token=TOKEN):
        return {"Authorization": f"Bearer {token}"}

    async def test_delivers_escaped_message(self):
        r = await self.client.post("/v1/webhook/notify", headers=self.auth(), json={
            "title": "Gemini <down>", "message": "exit & 1.2.3.4", "level": "critical"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.sent, ["🔴 Problem <b>Gemini &lt;down&gt;</b>\nexit &amp; 1.2.3.4"])

    async def test_doctor_buttons(self):
        r = await self.client.post("/v1/webhook/notify", headers=self.auth(), json={
            "message": "x", "buttons": [[{"text": "✅ Approve", "data": "td:ok:1793452470-387"}]]})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.markups, [{"inline_keyboard": [[{"text": "✅ Approve", "callback_data": "td:ok:1793452470-387"}]]}])

    async def test_buttons_cannot_forge_bot_callbacks(self):
        for buttons in ([[{"text": "x", "data": "del_ssh:1"}]], [[{"text": "x", "data": "td:ok:a b"}]],
                        [[{"text": "", "data": "td:ok:1"}]], "td:ok:1", [[]], [[{"text": "x", "data": "td:ok:1"}]] * 4):
            r = await self.client.post("/v1/webhook/notify", headers=self.auth(), json={"message": "x", "buttons": buttons})
            self.assertEqual(r.status, 400, buttons)
        self.assertEqual(self.sent, [])

    async def test_requires_webhook_token(self):
        for headers in ({}, self.auth("x" * 48), self.auth(CONTROL)):
            r = await self.client.post("/v1/webhook/notify", headers=headers, json={"message": "hi"})
            self.assertEqual(r.status, 401)
        self.assertEqual(self.sent, [])

    async def test_webhook_token_cannot_run_operations(self):
        r = await self.client.get("/v1/operations", headers=self.auth())
        self.assertEqual(r.status, 401)

    async def test_validation(self):
        h = self.auth()
        for body in ({}, {"message": ""}, {"message": 5}, {"message": "x", "level": "bogus"}, []):
            r = await self.client.post("/v1/webhook/notify", headers=h, json=body)
            self.assertEqual(r.status, 400, body)
        r = await self.client.post("/v1/webhook/notify", headers=h, json={"message": "x" * 4000})
        self.assertEqual(r.status, 413)

    async def test_disabled_without_token(self):
        client = await self.make("")
        r = await client.post("/v1/webhook/notify", headers=self.auth(), json={"message": "hi"})
        self.assertEqual(r.status, 404)

    async def test_delivery_failure_is_502(self):
        async def boom(text, markup=None):
            raise RuntimeError("telegram down")

        self.send = boom
        client = await self.make(TOKEN)
        r = await client.post("/v1/webhook/notify", headers=self.auth(), json={"message": "hi"})
        self.assertEqual(r.status, 502)

    async def test_rate_limit(self):
        h = self.auth()
        for _ in range(30):
            r = await self.client.post("/v1/webhook/notify", headers=h, json={"message": "hi"})
            self.assertEqual(r.status, 200)
        r = await self.client.post("/v1/webhook/notify", headers=h, json={"message": "hi"})
        self.assertEqual(r.status, 429)


if __name__ == "__main__":
    unittest.main()
