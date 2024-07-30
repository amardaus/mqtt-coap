import paho.mqtt.publish as publish
from datetime import datetime
from random import choice
from string import ascii_uppercase

broker = "192.168.187.101"
port = 1883
topic = "/test"
payload_length = 100

def generate_payload(len):
        dt = datetime.now()
        ts = datetime.timestamp(dt)
        random_string = "".join(choice(ascii_uppercase) for _ in range(1, len + 1))
        payload = str(ts) + " " + random_string
        return payload

payload = generate_payload(payload_length)
publish.single(topic, payload=payload, hostname=broker, port=port)
print("Message published")