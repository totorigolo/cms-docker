FROM ubuntu:16.04

MAINTAINER totorigolo <toto.rigolo@free.fr>

# CMS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential iso-codes shared-mime-info stl-manual cgroup-lite gettext  \
        postgresql postgresql-client texlive-latex-base a2ps                       \
        python2.7 python-dev libpq-dev libcups2-dev libyaml-dev libffi-dev         \
        python-pip python-pkg-resources python-setuptools python-wheel             \
    && rm -rf /var/lib/apt/lists/*


# Languages
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-8-jre openjdk-8-jdk \
        gcc-6-base                  \
        fpc                         \
        php7.0                      \
        haskell-platform            \
        python3.5                   \
        mono-devel                  \
    && rm -rf /var/lib/apt/lists/*


# CMS
RUN apt-get update && apt-get install -y --no-install-recommends git
ADD https://api.github.com/repos/totorigolo/cms/git/refs/heads/v1.3 /cms-version.json
RUN git clone --recursive https://github.com/totorigolo/cms.git -b v1.3 /cms
RUN cd /cms && pip2 install -r requirements.txt
RUN cd /cms && ./prerequisites.py install --as-root
RUN cd /cms && ./setup.py build && ./setup.py install && rm -rf /cms

## Copy the CMS configuration files generator
COPY generate-cms-conf.py /

## Create the log directory
RUN mkdir -p /var/local/log/cms/


# Mount the cgroups, required by the CMS sandbox
RUN cgroups-mount


# Run CMS
COPY ./entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
