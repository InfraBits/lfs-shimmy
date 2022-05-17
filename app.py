#!/usr/bin/env python3
"""
LFS Shimmy

This is a simple API that creates pre-signed S3 URLs based on Git LFS requests,
it implements the Git LFS Batch API with the Basic transfer adapter.

MIT License

Copyright (c) 2021 Infra Bits

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import boto3
import logging
import sys
from base64 import b64decode
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, make_response
from functools import wraps

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_envvar("LFS_SHIMMY_SETTINGS")
app.s3 = boto3.session.Session().client(
    service_name="s3",
    use_ssl=True,
    region_name=app.config.get("AWS_S3_REGION_NAME"),
    endpoint_url=app.config.get("AWS_S3_ENDPOINT_URL"),
    aws_access_key_id=app.config.get("AWS_S3_ACCESS_KEY_ID"),
    aws_secret_access_key=app.config.get("AWS_S3_SECRET_ACCESS_KEY"),
)


def _build_key(repo, id) -> str:
    """Generate the S3 key (path) for a given object."""
    return f"{repo}/{id}"


def _build_bucket(org) -> str:
    """Generate the S3 bucket for a given org."""
    return '-'.join([app.config.get("AWS_S3_BUCKET_PREFIX"), org]).lower()


def _object_exists(org, key):
    """Verify if a given key (path) exists, using the S3 API."""
    try:
        app.s3.head_object(Bucket=_build_bucket(org),
                           Key=key)
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise e
    else:
        return True


def _handle_object_upload(org, repo, object):
    """Generate pre-signed urls for an upload request, using the S3 API."""
    key = _build_key(repo, object["oid"])
    logger.info(f'Handling upload for {object["oid"]} ({key})')
    signed_url = app.s3.generate_presigned_url("put_object",
                                               Params={"Bucket": _build_bucket(org),
                                                       "Key": key},
                                               ExpiresIn=120)

    logger.info(f'Returning {signed_url} for {object["oid"]} upload')
    return None, {
        "upload": {"href": signed_url, "expires_in": 120},
        "verify": {
            "href": f"http{'s' if request.is_secure else ''}://{request.host}/{org}/{repo}/verify",
            "expires_in": 120,
        },
    }


def _handle_object_download(org, repo, object):
    """Generate pre-signed urls for a download request, using the S3 API."""
    key = _build_key(repo, object["oid"])
    logger.info(f'Handling download for {object["oid"]} ({key})')
    if not _object_exists(org, key):
        return {"code": 404, "message": "Object missing from store"}, None

    signed_url = app.s3.generate_presigned_url("get_object",
                                               Params={"Bucket": _build_bucket(org),
                                                       "Key": key},
                                               ExpiresIn=120)

    logger.info(f'Returning {signed_url} for {object["oid"]} download')
    return None, {"download": {"href": signed_url, "expires_in": 120}}


def verify_login(f):
    """Enforce HTTP basic authentication for a given endpoint."""

    def _get_credentials():
        """Decode & verify credentials for the current request."""
        if "Authorization" not in request.headers:
            logger.debug("No credentials found")
            return False, None, None

        try:
            credentials = request.headers.get("Authorization").split(" ", 1)[1]
            username, password = b64decode(credentials).decode("utf-8").split(":", 1)
        except Exception as e:
            logger.warning(f"Could not decode credentials: {e}")
            return True, None, None

        logger.info(f"Decoded credentials for {username}")
        return True, username, password

    @wraps(f)
    def decorated(*args, **kwargs):
        have_credentials, username, password = _get_credentials()
        if not have_credentials:
            return make_response("Unauthorized", 401)

        if kwargs.get('org') not in app.config.get("AUTHORIZED_PROJECTS").split(","):
            return make_response("Unknown Project", 404)

        if (
            username
            and password
            and f"{username}:{password}" in app.config.get("AUTHORIZED_USERS").split(";")
        ):
            logger.info(f"Login successful for {username}")
            return f(*args, **kwargs)

        return make_response("Access Denied", 403)

    return decorated


@app.route("/<org>/<repo>/objects/batch", methods=["POST"])
@verify_login
def batch(org, repo):
    """Git LFS API endpoint."""

    # Per https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md
    #   An optional Array of String identifiers for transfer adapters that the client has configured.
    #   If omitted, the basic transfer adapter MUST be assumed by the server.
    if not request.json["transfers"]:
        request.json["transfers"] = ["basic"]

    # We only implement the basic transfer adapter
    if "basic" not in request.json["transfers"]:
        logger.warning(f'Unsupported transfers type: {request.json["transfers"]}')
        return make_response(jsonify({"message": "Unsupported transfer method"}), 422)

    # Per https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md
    #   `operation` - Should be `download` or `upload`.
    if request.json["operation"] not in ("upload", "download"):
        logger.warning(f'Unsupported operation: {request.json["operation"]}')
        return make_response(jsonify({"message": "Invalid operation"}), 422)

    response_objects = []
    for object in request.json["objects"]:
        # For each requested object, pre-signed a POST or GET request
        if request.json["operation"] == "download":
            errors, actions = _handle_object_download(org, repo, object)
        else:
            errors, actions = _handle_object_upload(org, repo, object)

        response_object = {
            "oid": object["oid"],
            "size": object["size"],
            "authenticated": False,
        }
        if errors is not None:
            response_object["errors"] = errors
        if actions is not None:
            response_object["actions"] = actions
        response_objects.append(response_object)

    return jsonify({"transfer": "basic", "objects": response_objects})


@app.route("/<org>/<repo>/verify", methods=["POST"])
@verify_login
def verify(org, repo):
    """Object verification API endpoint."""
    key = _build_key(repo, request.json["oid"])
    logger.info(f'Handling {request.json["oid"]} ({key}) verification')
    if not _object_exists(org, key):
        return make_response(jsonify({"message": "Object missing from store"}), 404)
    return make_response("", 200)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    app.run()
