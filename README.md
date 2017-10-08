# CMS Docker image and AWS deployment

This repository defines a Docker image for CMS, based of my 
forked version. It also gives scripts for automatic deployment
to Amazon Web Services.

## How to use it?

Simply copy `sample-use.py`, modify it accordingly to your 
configuration, then run:

```commandline
# To generate the config, build the Docker container and deploy to Docker Hub
$ my-copy.sh -c my-operation-id "Operation title"

# To deploy
$ my-copy.sh -d my-operation-id "Operation title"

# To terminate the deployment
$ my-copy.sh -t my-operation-id "Operation title"

```
