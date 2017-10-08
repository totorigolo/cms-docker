#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright © 2017 Thomas Lacroix <toto.rigolo@free.fr>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
    Generate CMS configuration files from environment variables.
"""

import json
import os

import binascii


class Generator:
    def __init__(self):
        pass

    @staticmethod
    def generate_secret_key():
        return binascii.hexlify(os.urandom(16)).decode('utf-8')

    def generate_config(self, **config):
        try:
            ####################################################################################
            # System-wide configuration
    
            config['temp_dir'] = config.get('temp_dir', '/tmp')
    
            # Whether to have a backdoor (see doc for the risks).
            config['backdoor'] = config.get('backdoor', False) == 'True'
    
            ####################################################################################
            # AsyncLibrary

            config['core_services'] = config['core_services']
            config['other_services'] = config['other_services']
    
            ####################################################################################
            # Database
    
            # Connection string for the database.
            db_user = config.get('db_user', 'cmsuser')
            db_passwd = config['db_passwd']
            db_host = config.get('db_host', 'localhost')
            db_port = config.get('db_port', 5432)
            db_name = config.get('db_name', 'cmsdb')
            config['database'] = "postgresql+psycopg2://{u}:{pw}@{h}:{p}/{n}".format(
                u=db_user, pw=db_passwd, h=db_host, p=db_port, n=db_name)
    
            # Whether SQLAlchemy prints DB queries on stdout.
            config['database_debug'] = config.get('database_debug', False) == 'True'
    
            # Whether to use two-phase commit.
            config['twophase_commit'] = config.get('twophase_commit', False) == 'True'
    
            ####################################################################################
            # Worker
    
            # Don't delete the sandbox directory under /tmp/ when they
            # are not needed anymore. Warning: this can easily eat GB
            # of space very soon.
            config['keep_sandbox'] = config.get('keep_sandbox', False) == 'True'
    
            ####################################################################################
            # Sandbox
    
            # Do not allow contestants' solutions to write files bigger
            # than this size (expressed in KB; defaults to 10 MB).
            config['max_file_size'] = int(config.get('max_file_size', 10240))
    
            ####################################################################################
            # WebServers
    
            # This key is used to encode information that can be seen
            # by the user, namely cookies and auto-incremented
            # numbers. It should be changed for each contest.
            config['secret_key'] = config.get('secret_key', self.generate_secret_key())
    
            # Whether Tornado prints debug information on stdout.
            config['tornado_debug'] = config.get('tornado_debug', False) == 'True'
    
            ####################################################################################
            # ContestWebServer
    
            # Listening HTTP addresses and ports for the CWSs listed above
            # in core_services. If you access them through a proxy (acting
            # as a load balancer) running on the same host you could put
            # 127.0.0.1 here for additional security.
            config['contest_listen_address'] = config.get('contest_listen_address', [""])
            config['contest_listen_port'] = config.get('contest_listen_port', [8888])
    
            # Login cookie duration in seconds. The duration is refreshed
            # on every manual request.
            config['cookie_duration'] = int(config.get('cookie_duration', 10800))
    
            # If CWSs write submissions to disk before storing them in
            # the DB, and where to save them. %s = DATA_DIR.
            config['submit_local_copy'] = config.get('submit_local_copy', False) == 'True'
            config['submit_local_copy_path'] = config.get('submit_local_copy_path', "%s/submissions/")
    
            # The number of proxies that will be crossed before CWSs get
            # the request. This is used to decide whether to assume that
            # the real source IP address is the one listed in the request
            # headers or not. For example, if you're using nginx as a load
            # balancer, you will likely want to set this value to 1.
            config['num_proxies_used'] = int(config.get('num_proxies_used', 0))
    
            # Maximum size of a submission in bytes. If you use a proxy
            # and set these sizes to large values remember to change
            # client_max_body_size in nginx.conf too.
            config['max_submission_length'] = int(config.get('max_submission_length', 100000))
            config['max_input_length'] = int(config.get('max_input_length', 5000000))
    
            # STL documentation path in the system (exposed in CWS).
            config['stl_path'] = config.get('stl_path', '/usr/share/doc/stl-manual/html/')
    
            ####################################################################################
            # AdminWebServer
    
            # Listening HTTP address and port for the AWS. If you access
            # it through a proxy running on the same host you could put
            # 127.0.0.1 here for additional security.
            config['admin_listen_address'] = config.get('admin_listen_address', '')
            config['admin_listen_port'] = int(config.get('admin_listen_port', 8889))
    
            # Login cookie duration for admins in seconds.
            # The duration is refreshed on every manual request.
            config['admin_cookie_duration'] = int(config.get('admin_cookie_duration', 36000))
    
            ####################################################################################
            # ScoringService
    
            # List of URLs (with embedded username and password) of the
            # RWSs where the scores are to be sent. Don't include the
            # load balancing proxy (if any), just the backends. If any
            # of them uses HTTPS specify a file with the certificates
            # you trust.
            rk_user = config.get('rankings_user', 'cmsrankingsuser')
            rk_passwd = config.get('rankings_passwd', self.generate_secret_key())
            rk_host = config.get('rankings_host', 'localhost')
            rk_port = config.get('rankings_port', 8890)
            config['rankings'] = []
            # config['rankings'].append("http://{u}:{pw}@{h}:{p}".format(
            #     u=rk_user, pw=rk_passwd, h=rk_host, p=rk_port))  # TODO: Add optional ranking
            config['https_certfile'] = config.get('https_certfile', None)
    
            ####################################################################################
            # PrintingService
    
            # Maximum size of a print job in bytes.
            config['max_print_length'] = int(config.get('max_print_length', 10000000))
    
            # Printer name (can be found out using 'lpstat -p';
            # if None, printing is disabled)
            config['printer'] = config.get('printer', None)
    
            # Output paper size (probably A4 or Letter)
            config['paper_size'] = config.get('paper_size', 'A4')
    
            # Maximum number of pages a user can print per print job
            # (excluding the title page). Text files are cropped to this
            # length. Too long pdf files are rejected.
            config['max_pages_per_job'] = int(config.get('max_pages_per_job', 10))
            config['max_jobs_per_user'] = int(config.get('max_jobs_per_user', 10))
            config['pdf_printing_allowed'] = config.get('pdf_printing_allowed', False) == 'True'
    
            ####################################################################################
            ####################################################################################
            # Ranking config
    
            ranking_config = dict()
    
            ranking_config['bind_address'] = ''
            ranking_config['http_port'] = rk_port
            ranking_config['username'] = rk_user
            ranking_config['password'] = rk_passwd
    
            return config, ranking_config
        except KeyError as var:
            print('You must define the following variable: %s' % var)
            raise

    def create_config_files(self, **config):
        cms_config, rk_config = self.generate_config(**config)

        with open('cms.conf', 'w') as cms_conf:
            cms_conf.write(json.dumps(cms_config, indent=4, separators=(',', ': ')))

        with open('cms.ranking.conf', 'w') as cms_ranking_conf:
            cms_ranking_conf.write(json.dumps(rk_config, indent=4, separators=(',', ': ')))


if __name__ == '__main__':
    g = Generator()
    g.create_config_files()
