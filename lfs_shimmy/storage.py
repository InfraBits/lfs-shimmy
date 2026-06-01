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

import boto3
import logging
from botocore.exceptions import ClientError

from lfs_shimmy.config import settings, ProjectSettings
from lfs_shimmy.models import LFSObject

logger = logging.getLogger(__name__)

PRESIGNED_URL_EXPIRES_IN = 120

s3 = boto3.session.Session().client(
    service_name="s3",
    use_ssl=True,
    region_name=settings.s3.region_name,
    endpoint_url=settings.s3.endpoint_url,
    aws_access_key_id=settings.s3.access_key_id,
    aws_secret_access_key=settings.s3.secret_access_key,
)


def _build_object_key(project_settings: ProjectSettings, repo: str, object_id: str) -> str:
    """Generate the S3 key (path) for a given object."""
    if project_settings.prefix:
        return f"{project_settings.prefix}/{repo}/{object_id}"
    return f"{repo}/{object_id}"


def _object_exists(project_settings: ProjectSettings, repo: str, key: str) -> bool:
    """Verify if a given key (path) exists, using the S3 API."""
    try:
        s3.head_object(Bucket=project_settings.bucket_name, Key=_build_object_key(project_settings, repo, key))
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise
    return True


def _generate_presigned_url(operation: str, project_settings: ProjectSettings, repo: str, lfs_object: LFSObject) -> str:
    """Generate a pre-signed S3 URL for the given operation."""
    return s3.generate_presigned_url(
        operation,
        Params={
            "Bucket": project_settings.bucket_name,
            "Key": _build_object_key(project_settings, repo, lfs_object.oid),
        },
        ExpiresIn=PRESIGNED_URL_EXPIRES_IN,
    )
