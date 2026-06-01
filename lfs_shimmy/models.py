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

from pydantic import BaseModel, Field


class LFSObject(BaseModel):
    oid: str
    size: int


class BatchRequest(BaseModel):
    transfers: list[str] = Field(default=list)
    operation: str
    objects: list[LFSObject]


class VerifyRequest(BaseModel):
    oid: str
    size: int


class ObjectErrorResponse(BaseModel):
    code: int | None = Field(default=None, exclude=True)
    message: str


class ObjectResponse(BaseModel):
    href: str
    expires_in: int


class DownloadObjectResponse(BaseModel):
    download: ObjectResponse


class UploadObjectResponse(BaseModel):
    upload: ObjectResponse
    verify: ObjectResponse


class BatchResponseObject(BaseModel):
    oid: str
    size: int
    actions: UploadObjectResponse | DownloadObjectResponse | None = None
    errors: ObjectErrorResponse | None = None
    authenticated: bool = Field(default=False)


class BatchResponse(BaseModel):
    transfer: str
    objects: list[BatchResponseObject]
