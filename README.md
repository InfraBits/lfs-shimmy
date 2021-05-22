LFS Shimmy
==========

This is a simple API that creates pre-signed S3 URLs based on Git LFS requests,
it implements the Git LFS Batch API with the Basic transfer adapter.

A secondary API endpoint for object verification is also implemented,
for use via the Batch API.

Note: It does not currently implement the File Locking API.
