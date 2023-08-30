# pubsub_manager.py
import redis
import json
from .extensions import jwt, db, migrate, CONFIG, red


class PubSubManager:
    def __init__(self):
        self.redis = redis.Redis(host=CONFIG.REDIS_HOST, port=CONFIG.REDIS_PORT, db=CONFIG.REDIS_DB,
                                 password=CONFIG.REDIS_PASSWORD)
        self.pubsub = self.redis.pubsub()

    def publish_add_message(self, key, data):
        self.redis.publish("message", f" add {key} {json.dumps(data)}")

    def publish_remove_message(self, count, key):
        self.redis.publish("message", f"remove {count} message: {json.dumps(key)} ")

    def publish_update_message(self, key, new_key, data):
        self.redis.publish("message", f"update message {key} - > {new_key}")

    def subscribe_to_message_updates(self):
        self.pubsub.subscribe("message")
        return self.pubsub

    def listen(self):
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                data = message['data']
                # Xử lý thông điệp nhận được từ kênh "message"
                print("Received:", data)


pubsub_manager = PubSubManager()


def publish_add_message(key, data: dict):
    red.set(key, json.dumps(data))
    pubsub_manager.publish_add_message(key, data)


def publish_remove_message(keys: list):
    count = red.delete(*keys)
    pubsub_manager.publish_remove_message(count, keys)


def publish_update_message(key, data: dict):
    new_key = f"message:{data['message_id']}-{data['code_lang']}"
    if new_key != key:
        red.delete(key)
    red.set(new_key, json.dumps(data))
    pubsub_manager.publish_update_message(key, new_key, data)
