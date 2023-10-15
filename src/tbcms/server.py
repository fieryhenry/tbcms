import json
import os
import re
import time
from typing import Any, Optional

import flask
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
    path = os.environ.get("PRESENTS_PATH", get_file_path("presents.json"))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    item = {
        "presentCode": 1,
        "title": "Mailbox Private Server",
        "body": "Made by fieryhenry and made possible\nby jamestiotio's original work:\nhttps://github.com/jamestiotio/CITM",
        "createdAt": int(time.time()),
        "acceptedAt": 1,
        "items": [
            {"itemId": 22, "itemCategory": 0, "amount": 0, "title": "Catfood"},
            {"itemId": 22, "itemCategory": 0, "amount": 0, "title": "Catfood"},
        ],
    }
    data.insert(
        0,
        item,
    )
    return data


app = flask.Flask(__name__)


@app.route("/<path:path>")
def everything(path: str) -> Any:
    if path.startswith("/items/"):
        return items(path[7:])
    if "." in path.split("/")[0]:
        path = f"/items/{'/'.join(path.split('/')[1:])}"
        return items(path)
    return forward_request_rq(
        flask.request, "https://nyanko-items.ponosgames.com/" + path
    )


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

    presents = get_presents()

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
    path = path.replace("/om/", "/")
    path = path.replace("/m/", "/")

    return path


def run(
    debug: bool = False,
    port: int = 80,
    host: str = "0.0.0.0",
    path: Optional[str] = None,
) -> None:
    """Run the server"""
    if path is not None:
        os.environ["PRESENTS_PATH"] = os.path.abspath(path)
    else:
        path = os.environ.get("PRESENTS_PATH", get_file_path("presents.json"))
    app.run(debug=debug, host=host, port=port)
