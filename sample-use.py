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

import os
import sys

import Ec2ForCms
from Logger import log

if __name__ == '__main__':
    # Check the command args
    if len(sys.argv) != 4:
        log('critical', 'Usage: script.py -[c|d|t] deployment-id "Deployment title"\n'
            + '-c --config to create CMS config files, create a Docker container and push it.\n'
            + '-d --deploy to deploy CMS on AWS.\n'
            + '-t --terminate to terminate a deployment saved in <id>.json.')
        exit(1)

    # Get the action
    deploy = sys.argv[1] in ['-d', '--deploy']
    terminate = sys.argv[1] in ['-t', '--terminate']
    config = sys.argv[1] in ['-c', '--config']
    if not deploy and not terminate and not config:
        log('critical', 'First argument invalid. '
            + 'Candidates: -d (--deploy), -t (--terminate) and -c (--config).')
        exit(1)

    # Create an EC2 manager
    ec2Manager_id = sys.argv[2]
    ec2Manager_title = sys.argv[3]
    ec2Manager = Ec2ForCms.Manager(ec2Manager_id, ec2Manager_title)

    # Deploy or config
    if deploy or config:
        ec2Manager.up(
            amazon_image_id='<amazon_image_id>',
            certificate_arn='<certificate_arn>',
            main_instance_type='t2.micro',
            cws_instances_type='t2.micro', nb_cws_instances=3, nb_cws_per_instance=2,
            workers_instances_type='t2.micro', nb_workers_instances=2, nb_workers_per_instance=2,
            ssh_allowed_ips=['1.2.3.4/32'],
            admin_allowed_ips=['1.2.3.4/32'],
            cms_config={
                'db_user': 'cmsuser',
                'db_passwd': 'cmspasswd',
                'db_host': 'db.cms.host'
            },
            config_phase=config,
            cms_contest=1,
            docker_login='login', docker_password='<docker_password>'
        )

    # Build and push to Docker Hub
    if config:
        # Docker deployment
        docker_build_and_push = input('Do you want to Docker build and push with the new config? [Y/n]')
        deploy = docker_build_and_push.lower() not in ['d']

        image_name = input('Enter image name : [totorigolo/cms_cb]')
        if len(image_name) == 0:
            image_name = 'totorigolo/cms_cb'
        os.system('docker build -t {0} . && docker push {0}'.format(image_name))

    # Terminate a given deployment
    if terminate:
        ec2Manager.down()
