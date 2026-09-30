import resend

import lib.settings as settings


resend.api_key = settings.load_conf()['resend']['api_key']


def send_welcome_email(email_address):
    params: resend.Emails.SendParams = {
        "from": "Onboarding <onboarding@veilance.org>",
        "to": email_address,
        "subject": "Welcome to Veilance!",
        "html": open(settings.MAIL_TEMPLATES['welcome']).read()
    }
    try:
        resend.Emails.send(params)
    except:
        pass


def send_verification_code_email(code, email_address, expiration_time):
    params: resend.Emails.SendParams = {
        "from": "Onboarding <onboarding@veilance.org>",
        "to": email_address,
        "subject": "Verify your Veilance account",
        "html": open(settings.MAIL_TEMPLATES['verification']).read().replace(
            "!!CODE!!", code
        ).replace(
            "!!TIME!!", expiration_time
        ).replace(
            "!!BASE_URL", settings.load_conf()['resend']['base_url']
        )
    }
    try:
        resend.Emails.send(params)
    except:
        pass


def send_upgrade_email(email_address):
    params: resend.Emails.SendParams = {
        "from": "Onboarding <onboarding@veilance.org>",
        "to": email_address,
        "subject": "Your account has been upgraded",
        "html": open(settings.MAIL_TEMPLATES['upgrade']).read().replace(
            "!!BASE_URL", settings.load_conf()['resend']['base_url']
        )
    }
    try:
        resend.Emails.send(params)
    except:
        pass

