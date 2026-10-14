#!/bin/sh

# Deploy the specified file or directory to a remote server via SCP

# The parameters are obtained from the .env file in the same directory as this script.
# Here are the .env variables that should be set:
if false ; then
DEPLOY_HOST="optional_username@remote_host"
DEPLOY_DIR="/remote/path/to/deploy/to"
fi

# The script accepts a single argument: the source file or directory to deploy.
# The tool uses scp -r to copy the files. Existing files are overwritten.

# TODO:
# - Add possibilities to provide different remote host and directory.
# - Add error handling for the SCP command.
# - Consider allowing excluding certain files (like __pycache__) from deployment.
# - Optionally add a dry-run mode to preview the deployment.


script_dir=$(dirname "$0")

if [ -r "$script_dir/.env.example" ] && ! [ -f "$script_dir/.env" ]; then
    cp -v "$script_dir/.env.example" "$script_dir/.env"
    echo "Created .env from .env.example"
fi

if [ -r "$script_dir/.env" ]; then
    # Load environment variables from the .env file
    # set -a
    # shellcheck source=/dev/null
    # shellcheck source=.env.example    # This directive does not work. The previous one applies.
    . "$script_dir/.env"
    # set +a
fi

if [ -z "$DEPLOY_HOST" ] || [ -z "$DEPLOY_DIR" ]; then
    echo "Error: DEPLOY_HOST and DEPLOY_DIR must be set in the .env file" >&2
    exit 1
fi

if [ -z "$1" ]; then
    echo "Error: No source file or directory specified" >&2
    exit 1
fi

if [ ! -e "$1" ]; then
    echo "Error: Source file or directory $1 does not exist" >&2
    exit 1
fi

DEPLOY_DIR="${DEPLOY_DIR%/}"

# shellcheck disable=SC2029     # We want to expand $DEPLOY_DIR on the client side.
ssh "$DEPLOY_HOST" "mkdir -vp \"$DEPLOY_DIR\"" ||
{
    echo "Error: Failed to create remote directory $DEPLOY_DIR" >&2
    exit 1
}
# Note: There is no way to exclude files (like __pycache__) using this simple SCP approach.
# Maybe consider find ... | tar -c ... | ssh ... tar -x
scp -r "$1" "$DEPLOY_HOST":"$DEPLOY_DIR/"
