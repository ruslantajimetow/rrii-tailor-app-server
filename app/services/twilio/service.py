import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")

client = Client(ACCOUNT_SID, AUTH_TOKEN)


def send_verification_code(phone_number: str):
    verification = client.verify.v2.services(VERIFY_SERVICE_SID).verifications.create(
        to=phone_number,
        channel="sms",
    )
    return verification


def check_verification_code(phone_number: str, code: str):
    verification_check = client.verify.v2.services(
        VERIFY_SERVICE_SID
    ).verification_checks.create(
        to=phone_number,
        code=code,
    )
    return verification_check
