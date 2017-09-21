#!/usr/bin/env bash
# Docker entrypoint for CMS

# This will cause the shell to exit immediately if a simple command exits with a nonzero exit value.
set -e


## Generate CMS configuration
python generate-cms-conf.py
mv cms.conf cms.ranking.conf /usr/local/etc/


## Launch CMS if a contest id is given
# Get the contest to launch, defined in the CMS_contest env variable
contest="${CMS_contest:-0}"

if [ ${contest} -gt 0 ]; then
    # Optionnaly launch the Ranking Web Server
    if [ "${CMS_RWS:-OFF}" == "ON" ]; then
        cmsRankingWebServer &
    fi

    # Launch the logging service
    cmsLogService &

    # Lanch the resource service with the contest ID given in env
    cmsResourceService -a ${contest}
else
    # Launch a bash
    /bin/bash
fi
