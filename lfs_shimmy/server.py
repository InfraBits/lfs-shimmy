#!/usr/bin/env python3
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

import asyncio
import logging
from fastapi import FastAPI, Depends, Request
from fastapi.responses import Response

from starlette import status

from lfs_shimmy.auth import require_valid_user
from lfs_shimmy.config import ProjectSettings
from lfs_shimmy.models import (
    BatchRequest,
    VerifyRequest,
    LFSObject,
    ObjectErrorResponse,
    DownloadObjectResponse,
    ObjectResponse,
    UploadObjectResponse,
    BatchResponse,
    BatchResponseObject,
)
from lfs_shimmy.storage import _generate_presigned_url, _object_exists, PRESIGNED_URL_EXPIRES_IN

logger = logging.getLogger(__name__)

app = FastAPI()


async def _handle_object_upload(
    project_settings: ProjectSettings, project: str, repo: str, lfs_object: LFSObject, verify_url: str
) -> BatchResponseObject:
    """Generate pre-signed urls for an upload request, using the S3 API."""
    logger.info(f"Handling upload for {project}/{repo}: {lfs_object.oid}")
    signed_url = await asyncio.to_thread(_generate_presigned_url, "put_object", project_settings, repo, lfs_object)

    logger.debug(f"Returning {signed_url} for {lfs_object.oid} upload ({verify_url})")
    return BatchResponseObject(
        oid=lfs_object.oid,
        size=lfs_object.size,
        actions=UploadObjectResponse(
            upload=ObjectResponse(href=signed_url, expires_in=PRESIGNED_URL_EXPIRES_IN),
            verify=ObjectResponse(href=verify_url, expires_in=PRESIGNED_URL_EXPIRES_IN),
        ),
    )


async def _handle_object_download(
    project_settings: ProjectSettings, project: str, repo: str, lfs_object: LFSObject
) -> BatchResponseObject:
    """Generate pre-signed urls for a download request, using the S3 API."""
    logger.info(f"Handling download for {project}/{repo}: {lfs_object.oid}")

    exists = await asyncio.to_thread(_object_exists, project_settings, repo, lfs_object.oid)
    if exists:
        signed_url = await asyncio.to_thread(_generate_presigned_url, "get_object", project_settings, repo, lfs_object)
        logger.debug(f"Returning {signed_url} for {lfs_object.oid} download")
        return BatchResponseObject(
            oid=lfs_object.oid,
            size=lfs_object.size,
            actions=DownloadObjectResponse(
                download=ObjectResponse(href=signed_url, expires_in=PRESIGNED_URL_EXPIRES_IN)
            ),
        )

    logger.warning(f"Missing object for {project}/{repo}: {lfs_object.oid}")
    return BatchResponseObject(
        oid=lfs_object.oid,
        size=lfs_object.size,
        errors=ObjectErrorResponse(code=404, message="Object missing from store"),
    )


@app.post("/{project}/{repo}/objects/batch")
async def batch(
    project: str,
    repo: str,
    body: BatchRequest,
    request: Request,
    response: Response,
    project_settings=Depends(require_valid_user),
) -> BatchResponse | ObjectErrorResponse:
    """Git LFS API endpoint."""
    # We only implement the basic transfer adapter
    if "basic" not in body.transfers:
        logger.warning(f"Unsupported transfers type: {body.transfers}")
        response.status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
        return ObjectErrorResponse(message="Unsupported transfer method")

    # Per https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md `operation` - Should be `download` or `upload`.
    if body.operation not in ("upload", "download"):
        logger.warning(f"Unsupported operation: {body.operation}")
        response.status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
        return ObjectErrorResponse(message="Invalid operation")

    current_host = request.headers.get("host", request.url.hostname)
    verify_url = f"{request.url.scheme}://{current_host}/{project}/{repo}/verify"

    if body.operation == "download":
        tasks = [_handle_object_download(project_settings, project, repo, obj) for obj in body.objects]
    else:
        tasks = [_handle_object_upload(project_settings, project, repo, obj, verify_url) for obj in body.objects]

    response_objects = await asyncio.gather(*tasks)

    return BatchResponse(transfer="basic", objects=response_objects)


@app.post("/{project}/{repo}/verify")
def verify(
    project: str, repo: str, body: VerifyRequest, response: Response, project_settings=Depends(require_valid_user)
):
    """Object verification API endpoint."""
    logger.info(f"Handling {body.oid} verification")
    if _object_exists(project_settings, repo, body.oid):
        return Response(status_code=200)

    response.status_code = status.HTTP_404_NOT_FOUND
    return ObjectErrorResponse(message="Object missing from store")
