"""
LFS Shimmy

This is a simple API that creates pre-signed S3 URLs based on Git LFS requests,
it implements the Git LFS Batch API with the Basic transfer adapter.

MIT License

Copyright (c) 2026 Infra Bits

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

import base64
import hashlib

from fastapi import HTTPException, Request
from lfs_shimmy.config import settings, ProjectSettings


def get_login_details(request: Request) -> tuple[str | None, str | None]:
    if authorization_header := request.headers.get("Authorization"):
        if authorization_header.startswith("Basic "):
            authorization_header = authorization_header.removeprefix("Basic ")

            try:
                credentials = base64.b64decode(authorization_header).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None, None

            if ":" in credentials:
                username, password = credentials.split(":", 1)
                return username, password
    return None, None


def have_valid_login_details(username: str, password: str) -> bool:
    if user_passwords := settings.users.get(username):
        hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hashed_password in user_passwords
    return False


def require_valid_user(project: str, repo: str, request: Request) -> ProjectSettings:
    username, password = get_login_details(request)
    if not have_valid_login_details(username, password):
        raise HTTPException(status_code=401, detail="Unauthorized")

    if project_settings := settings.projects.get(f"{project}/{repo}"):
        if username not in project_settings.authorized_users:
            raise HTTPException(status_code=403, detail="Access Denied")
        return project_settings

    raise HTTPException(status_code=404, detail="Unknown Project")
