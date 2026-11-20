FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# The base image ships a Yarn apt source whose signing key no longer verifies, which breaks apt-get in the features.
RUN grep -rl "dl.yarnpkg.com" /etc/apt/sources.list.d/ | xargs -r rm -f
