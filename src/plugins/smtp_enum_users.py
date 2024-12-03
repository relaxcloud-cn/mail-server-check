import re
from typing import List, Tuple

from loguru import logger
from pwnlib.tubes.remote import remote

STATUS_CODES = {
    "ERROR": 1,
    "NOTPERMITTED": 2,
    "VALID": 3,
    "INVALID": 4,
    "UNKNOWN": 5,
    "AUTHENTICATION": 6,
}


def get_method():
    methods = ["RCPT", "VRFY", "EXPN"]
    return methods


def do_gnrc(sock, command, username, domain) -> Tuple[str, str]:
    combinations = [username, f"{username}@{domain}"]

    for combination in combinations:
        cmd = f"{command} {combination}".encode("utf-8")
        logger.debug(cmd)
        sock.sendline(cmd)
        response = sock.recvline().decode()
        logger.debug(response)

        if re.match(r"^530", response):
            return STATUS_CODES["AUTHENTICATION"], None

        if (
            re.match(r"^502", response)
            or re.match(r"^252", response)
            or re.match(r"^550", response)
        ):
            return STATUS_CODES["NOTPERMITTED"], None

        if re.match(r"^250", response):
            return STATUS_CODES["VALID"], combination

        return STATUS_CODES["ERROR"], response


def do_expn(sock, username, domain):
    return do_gnrc(sock, "EXPN", username, domain)


def do_vrfy(sock, username, domain):
    return do_gnrc(sock, "VRFY", username, domain)


def do_rcpt(sock, username, domain):
    t = b"EHLO 163.com"
    logger.debug(t)
    sock.sendline(t)
    logger.debug(sock.recvline_startswith(b"250 "))

    sock.sendline(b"MAIL FROM:<postmaster@163.com>")
    response = sock.recvline().decode()
    logger.debug(response)

    if re.match(r"^530", response):
        return STATUS_CODES["AUTHENTICATION"], None
    if not re.match(r"^250", response):
        return STATUS_CODES["NOTPERMITTED"], None

    t = f"RCPT TO:<{username}@{domain}>".encode("utf-8")
    logger.debug(t)
    sock.sendline(t)
    response = sock.recvline().decode()
    logger.debug(response)

    if re.match(r"^550", response):
        return STATUS_CODES["UNKNOWN"], None
    if re.match(r"^553", response):
        return STATUS_CODES["NOTPERMITTED"], None
    if re.match(r"^250", response):
        return STATUS_CODES["VALID"], username

    return STATUS_CODES["ERROR"], response


def enumerate_smtp_users(host, port, domain, usernames, timeout=2) -> List[str]:
    """
    枚举 SMTP 用户，返回有效用户邮箱列表
    """
    methods = get_method()
    users = []

    with remote(host, port, timeout=timeout) as sock:
        logger.debug(sock.recvline())  # Wait for the banner

        can_exploit_method = {method: True for method in methods}
        status, response = None, None
        for username in usernames:
            for method in methods:
                if not can_exploit_method[method]:  # 无法利用
                    continue
                if method == "RCPT":
                    status, response = do_rcpt(sock, username, domain)
                elif method == "VRFY":
                    status, response = do_vrfy(sock, username, domain)
                elif method == "EXPN":
                    status, response = do_expn(sock, username, domain)

                if status == STATUS_CODES["VALID"]:
                    users.append(response)

                if status == STATUS_CODES["AUTHENTICATION"]:
                    print("Authentication required, cannot enumerate users.")
                    can_exploit_method[method] = False

                if status == STATUS_CODES["NOTPERMITTED"]:  # VRFY/EXPN 无法利用
                    can_exploit_method[method] = False
                status, response = None, None

    return [f"{user}@{domain}" for user in users if user is not None]
