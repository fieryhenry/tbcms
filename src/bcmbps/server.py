import json
import os
import re
import shutil
import time
from typing import Any, Optional

import flask
import jwt
import requests


def get_files_folder() -> str:
    """Get the path to the files folder

    Returns:
        str: The path to the files folder
    """
    file = os.path.realpath(__file__)
    path = os.path.dirname(file)
    path = os.path.join(path, "files")
    return path


def get_file_path(path: str) -> str:
    """Get the path to a file in the files folder

    Args:
        path (str): The path to the file

    Returns:
        str: The path to the file
    """
    path = os.path.join(get_files_folder(), path)
    return path


def get_presents() -> list[dict[str, Any]]:
    """Get the presents from the presents.json file

    Returns:
        list[dict[str, Any]]: The presents
    """
    path = get_file_path("presents.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    item = {
        "id": 1,
        "title": "Mailbox Private Server",
        "body": "Made by fieryhenry and made possible\nby jamestiotio's original work:\nhttps://github.com/jamestiotio/CITM",
        "createdAt": int(time.time()),
        "items": [{"itemId": 22, "itemCategory": 0, "amount": 0, "title": "Catfood"}],
    }
    data.insert(
        0,
        item,
    )
    return data


def save_presents(path: str):
    """Save the presents to the presents.json file

    Args:
        path (str): The path to the presents
    """
    if path == get_file_path("presents.json"):
        return
    shutil.copy(
        path,
        get_file_path("presents.json"),
    )


app = flask.Flask(__name__)


@app.route("/items/<path:path>")
@app.route("/items/")
def items(path: str = "") -> Any:
    """Handle the items endpoint

    Args:
        path (str, optional): The path to the endpoint. Defaults to "".

    Returns:
        Any: The response
    """
    path = fix_path(path)
    if "presents/count" in path:
        return items_presents_count()
    if "presents/reception" in path:
        return items_presents_reception()
    if "presents" in path:
        return items_presents()
    return forward_request_rq(
        flask.request, "https://nyanko-items.ponosgames.com/" + path
    )


def read_auth_header() -> dict[str, Any]:
    """Read the Authorization header

    Returns:
        dict[str, Any]: The data in the header
    """
    auth_header = flask.request.headers.get("Authorization")
    if auth_header is None:
        return {}

    match = re.match(r"Bearer (?P<token>.+)", auth_header)
    if match is None:
        return {}

    token = match.group("token")
    if token is None:
        return {}

    data = jwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})
    return data


def get_account_code(token: dict[str, Any]) -> str:
    """Get the account code from the token

    Args:
        token (dict[str, Any]): The token

    Returns:
        str: The account code
    """
    return token.get("accountCode", "")


def get_country_code(token: dict[str, Any]) -> str:
    """Get the country code from the token

    Args:
        token (dict[str, Any]): The token

    Returns:
        str: The country code
    """
    client_info: dict[str, Any] = token.get("clientInfo", {})
    client: dict[str, Any] = client_info.get("client", {})
    country_code: str = client.get("countryCode", "")
    return country_code


def get_version(token: dict[str, Any]) -> str:
    """Get the version from the token

    Args:
        token (dict[str, Any]): The token

    Returns:
        str: The version
    """
    client_info: dict[str, Any] = token.get("clientInfo", {})
    client: dict[str, Any] = client_info.get("client", {})
    version: str = client.get("version", "")
    return version


def items_presents_count() -> Any:
    """Handle the items/presents/count endpoint

    Returns:
        Any: The response
    """
    nonce = flask.request.args.get("nonce")
    if nonce is None:
        return "nonce is None"

    json_data = {
        "statusCode": 1,
        "nonce": nonce,
        "payload": {
            "count": len(get_presents()),
        },
        "timestamp": int(time.time()),
    }

    body = json.dumps(json_data).encode()

    headers = {
        "Content-Type": "application/json",
        "Nyanko-Signature": "A",
    }

    return flask.Response(body, status=200, headers=headers)


def items_presents() -> Any:
    """Handle the items/presents endpoint

    Returns:
        Any: The response
    """
    nonce = flask.request.args.get("nonce")
    if nonce is None:
        return "nonce is None"

    auth_header = read_auth_header()
    account_code = get_account_code(auth_header)
    country_code = get_country_code(auth_header)
    version = get_version(auth_header)

    presents = get_presents()
    for present in presents:
        present["country"] = country_code
        present["clientVersion"] = version
        present["accountId"] = account_code

    json_data = {
        "statusCode": 1,
        "nonce": nonce,
        "payload": {
            "presents": presents,
        },
        "timestamp": int(time.time()),
    }

    body = json.dumps(json_data).encode()

    headers = {
        "Content-Type": "application/json",
        "Nyanko-Signature": "A",
    }

    return flask.Response(body, status=200, headers=headers)


def items_presents_reception() -> Any:
    """Handle the items/presents/reception endpoint

    Returns:
        Any: The response
    """
    nonce = flask.request.args.get("nonce")
    if nonce is None:
        return "nonce is None"

    json_data = {
        "statusCode": 1,
        "nonce": nonce,
        "timestamp": int(time.time()),
    }

    body = json.dumps(json_data).encode()

    headers = {
        "Content-Type": "application/json",
        "Nyanko-Signature": "A",
    }

    return flask.Response(body, status=200, headers=headers)


def forward_request(
    url: str,
    args: dict[str, Any],
    method: str,
    content: bytes,
    headers: dict[str, Any],
) -> flask.Response:
    """Forward a request to another server

    Args:
        url (str): URL to forward to
        args (dict[str, Any]): HTTP arguments
        method (str): HTTP method
        content (bytes): HTTP content
        headers (dict[str, Any]): HTTP headers

    Returns:
        flask.Response: The response
    """
    real_response = requests.request(
        method,
        url,
        params=args,
        headers=headers,
        data=content,
        timeout=5,
    )
    real_headers = dict(real_response.headers)
    real_content = real_response.content
    real_response_code = real_response.status_code
    real_headers.pop("Transfer-Encoding", None)

    real_headers["Nyanko-Signature"] = "A"
    return flask.Response(real_content, status=real_response_code, headers=real_headers)


def forward_request_rq(request: flask.Request, url: str) -> flask.Response:
    """Forward a request to another server

    Args:
        request (flask.Request): The request to forward
        url (str): URL to forward to

    Returns:
        flask.Response: The response
    """
    args = request.args
    method = request.method
    content = request.get_data()
    headers = request.headers

    return forward_request(url, args, method, content, headers)


def fix_path(path: str) -> str:
    """Fix the path, removing padding underscores and glitched stack string stuff?

    Args:
        path (str): The path to fix

    Returns:
        str: The fixed path
    """
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path + "/"
    path = re.sub(r"/_+", "/", path)
    path = path.replace("/.com/", "/")  # idk why this happens
    path = path.replace("/om/", "/")  # idk why this happens

    return path


def run(
    debug: bool = False,
    port: int = 80,
    host: str = "0.0.0.0",
    presents_path: Optional[str] = None,
) -> None:
    """Run the server"""
    if presents_path is not None:
        save_presents(presents_path)
    app.run(debug=debug, host=host, port=port)
