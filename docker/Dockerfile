FROM ghcr.io/infrabits/python3-alpine:3.10

COPY . /opt/lfs-shimmy/
WORKDIR /opt/lfs-shimmy

# Runtime path
ENV LFS_SHIMMY_SETTINGS=/opt/lfs-shimmy/lfs-shimmy.cfg

# System dependencies
RUN apk add gcc build-base python3-dev

# Python dependencies
RUN pip install --upgrade pip
RUN pip install --upgrade -r requirements.txt -r requirements-prod.txt
RUN rm -rf /root/.cache/pip

# Runtime
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/opt/lfs-shimmy/app.py"]
