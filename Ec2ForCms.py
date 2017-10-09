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
    Script for automated deployment of CMS into Amazon EC2.
"""

import threading
import datetime
import json
import os
import stat

import boto3

import CmsConf
from Logger import log


class Manager:
    def __init__(self, id, title):
        self.title = title
        self.ec2r = boto3.resource('ec2')
        self.ec2c = boto3.client('ec2')
        self.elb = boto3.client('elbv2')
        self.state_dict = {}
        self.date = datetime.datetime.now().strftime('%d-%m-%y-%Hh%M')
        self.id = id  # + '-' + self.date

    def up(self, amazon_image_id, certificate_arn,
           main_instance_type,
           cws_instances_type, nb_cws_instances, nb_cws_per_instance,
           workers_instances_type, nb_workers_instances, nb_workers_per_instance,
           ssh_allowed_ips, admin_allowed_ips,
           cms_config, config_phase,
           docker_login, docker_password,
           cms_contest):
        """
        Create a VPC, subnet, security group and launch the necessary instances
        for a contest having :nb_contestants contestants, and installing and
        launching the CMS Docker image on them.

        :param amazon_image_id: The Amazon AMI to be deployed on each of the instances.
        :param certificate_arn: The ARN of the certificate used by the Application Load Balancer
        :param main_instance_type: The main instance type.
        :param cws_instances_type: The CWS instances type.
        :param int nb_cws_instances: The number of CMS CWS instances.
        :param int nb_cws_per_instance: The number of CMS CWS services per instances.
        :param workers_instances_type: The workers instances type.
        :param int nb_workers_instances: The number of CMS workers instances.
        :param int nb_workers_per_instance: The number of CMS workers per instances.
        :param ssh_allowed_ips: A list of IP allowed to connect via SSH (must be "1.2.3.4/5").
        :param admin_allowed_ips: A list of IP allowed to connect via HTTP(S) (must be "1.2.3.4/5").
        :param cms_config: Dictionnary overriding CMS default config.
        :param config_phase: Weither to just generate the config or to deploy the instances on AWS.
        :param docker_login: The Docker Hub login.
        :param docker_password: The Docker Hub password.
        :param cms_contest: The CMS contest to launch.
        """

        # There can't be less than 2 CWS instances for Amazon Load Balancer
        if nb_cws_instances < 2:
            log('critical', "There can't be less than 2 CWS instances. Aborting.")
            exit(1)

        # Print a summary
        log('info',
            'Brief summary before execution:\n' +
            '  + 1 main instance\n' +
            '  + %d workers instances\n' % nb_workers_instances +
            '  + %d CWS instances\n' % nb_cws_instances +
            '  ---------------------------\n' +
            '  = %d instances\n' % (1 + nb_workers_instances + nb_cws_instances)
            )
        if input('Do you accept this configuration? [Y/n]').lower() not in ['', 'y', 'yes']:
            log('info', 'Operation cancelled.')
            return

        # Check if the user is on an authorized IP
        if input('Is your IP authorized? [Y/n]').lower() not in ['', 'y', 'yes']:
            log('info', 'Operation cancelled.')
            return

        # Compute private IPs for services
        main_instance_ip = '10.0.1.5'
        workers_instance_ips = ['10.0.1.' + str(i + 11) for i in range(nb_workers_instances)]
        cws1_instance_ips = ['10.0.2.' + str(i + 11) for i in range(nb_cws_instances // 2 + nb_cws_instances % 2)]
        cws2_instance_ips = ['10.0.3.' + str(i + 11) for i in range(nb_cws_instances // 2)]
        self.state_dict['main_instance_ip'] = main_instance_ip
        self.state_dict['workers_instance_ips'] = workers_instance_ips
        self.state_dict['cws1_instance_ips'] = cws1_instance_ips
        self.state_dict['cws2_instance_ips'] = cws2_instance_ips

        def up_ec2():
            # Create the VPC
            vpc_cidr_block = '10.0.0.0/16'
            vpc = self.ec2r.create_vpc(CidrBlock=vpc_cidr_block)
            self.state_dict['vpc_id'] = vpc.id
            log('success', "VPC created with ID '%s'." % vpc.id)

            # Create the Internet gateway
            gateway = self.ec2r.create_internet_gateway()
            gateway.attach_to_vpc(VpcId=vpc.id)
            self.state_dict['gateway_id'] = gateway.id
            log('success', "Internet gateway created with ID '%s'." % gateway.id)

            ############################################################################################################
            # Main subnet

            # Create the main subnet
            main_cidr_block = '10.0.1.0/24'
            main_subnet = vpc.create_subnet(CidrBlock=main_cidr_block, AvailabilityZone='eu-central-1a')
            self.state_dict['main_subnet_id'] = main_subnet.id
            log('success', "Main subnet created with ID '%s'." % main_subnet.id)

            # Create the main subnet routing table
            main_route_table = self.ec2r.create_route_table(VpcId=vpc.id)
            self.state_dict['main_route_table_id'] = main_route_table.id
            log('success', "Main subnet route table created with ID '%s'." % main_route_table.id)
            main_route_table_association = main_route_table.associate_with_subnet(SubnetId=main_subnet.id)
            self.state_dict['main_route_table_association_id'] = main_route_table_association.id
            log('success', "Main subnet route table associated to subnet (%s)." % main_route_table_association.id)
            main_route_gateway = main_route_table.create_route(
                GatewayId=gateway.id, DestinationCidrBlock='0.0.0.0/0')
            log('success', "Main subnet route table, new route to the Internet Gateway.")

            ############################################################################################################
            # CWS1 subnet

            # Create the cws subnet 1
            cws1_cidr_block = '10.0.2.0/24'
            cws1_subnet = vpc.create_subnet(CidrBlock=cws1_cidr_block, AvailabilityZone='eu-central-1b')
            self.state_dict['cws1_subnet_id'] = cws1_subnet.id
            log('success', "CWS subnet 1 created with ID '%s'." % cws1_subnet.id)

            # Create the main subnet routing table
            cws1_route_table = self.ec2r.create_route_table(VpcId=vpc.id)
            self.state_dict['cws1_route_table_id'] = cws1_route_table.id
            log('success', "CWS subnet 1 route table created with ID '%s'." % cws1_route_table.id)
            cws1_route_table_association = cws1_route_table.associate_with_subnet(SubnetId=cws1_subnet.id)
            self.state_dict['cws1_route_table_association_id'] = cws1_route_table_association.id
            log('success', "CWS subnet 1 route table associated to subnet (%s)." % cws1_route_table_association.id)
            cws1_route_gateway = cws1_route_table.create_route(
                GatewayId=gateway.id, DestinationCidrBlock='0.0.0.0/0')
            log('success', "CWS subnet 1 route table, new route to the Internet Gateway.")

            ############################################################################################################
            # CWS2 subnet

            # Create the cws subnet 2
            cws2_cidr_block = '10.0.3.0/24'
            cws2_subnet = vpc.create_subnet(CidrBlock=cws2_cidr_block, AvailabilityZone='eu-central-1c')
            self.state_dict['cws2_subnet_id'] = cws2_subnet.id
            log('success', "CWS subnet 2 created with ID '%s'." % cws2_subnet.id)

            # Create the main subnet routing table
            cws2_route_table = self.ec2r.create_route_table(VpcId=vpc.id)
            self.state_dict['cws2_route_table_id'] = cws2_route_table.id
            log('success', "CWS subnet 2 route table created with ID '%s'." % cws2_route_table.id)
            cws2_route_table_association = cws2_route_table.associate_with_subnet(SubnetId=cws2_subnet.id)
            self.state_dict['cws2_route_table_association_id'] = cws2_route_table_association.id
            log('success', "CWS subnet 2 route table associated to subnet (%s)." % cws2_route_table_association.id)
            cws2_route_gateway = cws2_route_table.create_route(
                GatewayId=gateway.id, DestinationCidrBlock='0.0.0.0/0')
            log('success', "CWS subnet 2 route table, new route to the Internet Gateway.")

            ############################################################################################################

            # Create the security group
            security_group = self.ec2r.create_security_group(GroupName=self.title,
                                                             Description=self.title,
                                                             VpcId=vpc.id)
            self.state_dict['security_group_id'] = security_group.id
            log('success', "Security group created with ID '%s' in VPC '%s'." %
                (security_group.id, vpc.id))

            # Add security rules
            self.ec2c.authorize_security_group_ingress(
                GroupId=security_group.id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 13800,
                     'ToPort': 13800,
                     'IpRanges': [{'CidrIp': ip} for ip in admin_allowed_ips]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': ip} for ip in ssh_allowed_ips]}
                ])
            self.ec2c.authorize_security_group_ingress(
                GroupId=security_group.id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 9000,
                     'ToPort': 9000 + nb_cws_instances * nb_cws_per_instance - 1,
                     'IpRanges': [{'CidrIp': ip} for ip in admin_allowed_ips]}
                ])
            self.ec2c.authorize_security_group_ingress(
                GroupId=security_group.id,
                CidrIp='10.0.0.0/16',
                IpProtocol='-1',
                ToPort=-1
            )
            log('success', 'Ingress successfully set in security group.')
            log('info', '%s allowed in security group for HTTP(S) access.'
                % str(admin_allowed_ips))
            log('info', '%s allowed in security group for SSH access.'
                % str(ssh_allowed_ips))

            # Create the keypair
            keypair = self.ec2c.create_key_pair(KeyName=self.id + '_keypair')
            with open(keypair['KeyName'] + '.pem', 'w') as f:
                f.write(keypair['KeyMaterial'])
            os.chmod(keypair['KeyName'] + '.pem', stat.S_IRUSR | stat.S_IWUSR)
            self.state_dict['keypair_name'] = keypair['KeyName']
            log('success', "Keypair '%s' created." % keypair['KeyName'])

            # Launch the master instance
            main_instances = self.ec2r.create_instances(
                ImageId=amazon_image_id,
                InstanceType=main_instance_type,
                Placement={'AvailabilityZone': 'eu-central-1a'},
                MinCount=1,
                MaxCount=1,
                KeyName=self.state_dict['keypair_name'],
                NetworkInterfaces=[{
                    'AssociatePublicIpAddress': True,
                    'SubnetId': main_subnet.id,
                    'Groups': [security_group.id],
                    'DeviceIndex': 0,
                    'PrivateIpAddress': main_instance_ip
                }]
            )
            main_instance_id = main_instances[0].id
            self.state_dict['main_instance_id'] = main_instance_id
            log('success', 'Main instance launched.')

            # Launch the worker instances
            self.state_dict['worker_instances_ids'] = []
            for ip in workers_instance_ips:
                worker_instance = self.ec2r.create_instances(
                    ImageId=amazon_image_id,
                    InstanceType=workers_instances_type,
                    Placement={'AvailabilityZone': 'eu-central-1a'},
                    MinCount=1,
                    MaxCount=1,
                    KeyName=self.state_dict['keypair_name'],
                    NetworkInterfaces=[{
                        'AssociatePublicIpAddress': True,
                        'SubnetId': main_subnet.id,
                        'Groups': [security_group.id],
                        'DeviceIndex': 0,
                        'PrivateIpAddress': ip
                    }]
                )
                self.state_dict['worker_instances_ids'].append(worker_instance[0].id)
            log('success', '%d worker instances launched.' % nb_workers_instances)

            # Launch the cws1 instances
            self.state_dict['cws1_instances_ids'] = []
            for ip in cws1_instance_ips:
                cws1_instance = self.ec2r.create_instances(
                    ImageId=amazon_image_id,
                    InstanceType=cws_instances_type,
                    Placement={'AvailabilityZone': 'eu-central-1b'},
                    MinCount=1,
                    MaxCount=1,
                    KeyName=self.state_dict['keypair_name'],
                    NetworkInterfaces=[{
                        'AssociatePublicIpAddress': True,
                        'SubnetId': cws1_subnet.id,
                        'Groups': [security_group.id],
                        'DeviceIndex': 0,
                        'PrivateIpAddress': ip
                    }]
                )
                self.state_dict['cws1_instances_ids'].append(cws1_instance[0].id)
            log('success', '%d CWS #1 instances launched.' % len(self.state_dict['cws1_instances_ids']))

            # Launch the cws2 instances
            self.state_dict['cws2_instances_ids'] = []
            for ip in cws2_instance_ips:
                cws2_instance = self.ec2r.create_instances(
                    ImageId=amazon_image_id,
                    InstanceType=cws_instances_type,
                    Placement={'AvailabilityZone': 'eu-central-1c'},
                    MinCount=1,
                    MaxCount=1,
                    KeyName=self.state_dict['keypair_name'],
                    NetworkInterfaces=[{
                        'AssociatePublicIpAddress': True,
                        'SubnetId': cws2_subnet.id,
                        'Groups': [security_group.id],
                        'DeviceIndex': 0,
                        'PrivateIpAddress': ip
                    }]
                )
                self.state_dict['cws2_instances_ids'].append(cws2_instance[0].id)
            log('success', '%d CWS #2 instances launched.' % len(self.state_dict['cws2_instances_ids']))

            # Wait until all the instances are running
            self.save_to_file()
            instances_ids = ([main_instance_id]
                             + self.state_dict['worker_instances_ids']
                             + self.state_dict['cws1_instances_ids']
                             + self.state_dict['cws2_instances_ids'])
            if len(instances_ids) > 0:
                log('info', 'Waiting for the instances to start...')
                waiter = self.ec2c.get_waiter("instance_status_ok")
                waiter.wait(InstanceIds=instances_ids)
                log('info', 'All the instances are running.')

            # Get the instances public IPs
            self.state_dict['instances_ips'] = []
            for instance_id in instances_ids:
                instance = self.ec2r.Instance(instance_id)
                self.state_dict['instances_ips'].append({
                    'public': instance.public_ip_address,
                    'private': instance.private_ip_address
                })
            log('info', 'Instances IPs: %s' % str(self.state_dict['instances_ips']))

            # Launch commands on all the instances
            def configure_by_ssh(ips):
                ports = ([8888, 8889,
                          29000, 28000, 28500, 22000, 25000, 21100, 28600, 25123, 27501]
                         + [9000 + i for i in range(nb_cws_per_instance * nb_cws_instances)]
                         + [26000 + shard for shard in range(20)]
                         + [21000 + shard for shard in range(20)])
                public_ip = ips['public']
                private_ip = ips['private']
                log('success', 'Configuring instance %s by SSH...' % ip)
                command_1 = 'ssh -o "StrictHostKeyChecking no" -i "{pem}.pem" ec2-user@{ip} "{command}"'.format(
                    pem=self.state_dict['keypair_name'],
                    ip=public_ip,
                    command=("sudo yum update -y && "
                             + "sudo yum install -y docker && "
                             + "sudo service docker start && "
                             + "sudo usermod -a -G docker ec2-user && "
                             + "exit")
                )
                command_2 = 'ssh -o "StrictHostKeyChecking no" -i "{pem}.pem" ec2-user@{ip} "{command}"'.format(
                    pem=self.state_dict['keypair_name'],
                    ip=public_ip,
                    command=('docker login -u \\"{u}\\" -p \\"{p}\\"'.format(u=docker_login, p=docker_password)
                             + " && "
                             + "docker run -d --privileged --net=host "
                             + " ".join("-p {p}:{p}".format(ip=private_ip, p=port) for port in ports) + " "
                             + "-e CMS_contest=%d " % cms_contest
                             + "totorigolo/cms_cb")
                )
                os.system(command_1)
                os.system(command_2)
                log('success', 'Instance %s configured by SSH.' % public_ip)

            threads = []
            for ips in self.state_dict['instances_ips']:
                thread = threading.Thread(target=configure_by_ssh, args=[ips])
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()

        def up_lb():
            required = ['vpc_id', 'cws1_subnet_id', 'cws2_subnet_id',
                        'cws1_instances_ids', 'cws2_instances_ids']
            for requirement in required:
                if requirement not in self.state_dict:
                    log('critical', "Required '%s' not started! Aborting." % requirement)
                    return

            # Create the security group
            lb_security_group = self.ec2r.create_security_group(GroupName=self.title + ' - LB',
                                                                Description='CMS LB security group',
                                                                VpcId=self.state_dict['vpc_id'])
            self.state_dict['lb_security_group_id'] = lb_security_group.id
            log('success', "LB security group created with ID '%s' in VPC '%s'." %
                (lb_security_group.id, self.state_dict['vpc_id']))
            self.ec2c.authorize_security_group_ingress(
                GroupId=lb_security_group.id,
                CidrIp='0.0.0.0/0',
                IpProtocol='-1',
                ToPort=-1
            )
            log('success', 'Ingress successfully set in LB security group.')

            # Create the load balancer
            load_balancers = self.elb.create_load_balancer(
                Name=self.id + '-lb',
                SecurityGroups=[lb_security_group.id],
                Subnets=[
                    self.state_dict['cws1_subnet_id'],
                    self.state_dict['cws2_subnet_id']
                ])
            load_balancer_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
            self.state_dict['load_balancer_arn'] = load_balancer_arn
            load_balancer_dnsname = load_balancers['LoadBalancers'][0]['DNSName']
            self.state_dict['load_balancer_dnsname'] = load_balancer_dnsname
            log('success', "Load balancer created with ARN '%s'." % load_balancer_arn)

            # Create the target group
            target_groups = self.elb.create_target_group(
                Name=self.id + '-tg',
                Protocol='HTTP',
                Port=8888,
                VpcId=self.state_dict['vpc_id'],
                TargetType='instance')
            target_group_arn = target_groups['TargetGroups'][0]['TargetGroupArn']
            self.state_dict['target_group_arn'] = target_group_arn
            log('success', "Target group created with ARN '%s'." % target_group_arn)

            # Register targets to the target group
            targets = []
            target_port = 9000
            for id in self.state_dict['cws1_instances_ids']:
                for _ in range(nb_cws_per_instance):
                    targets.append({'Id': id, 'Port': target_port})
                    target_port += 1
            for id in self.state_dict['cws2_instances_ids']:
                for _ in range(nb_cws_per_instance):
                    targets.append({'Id': id, 'Port': target_port})
                    target_port += 1
            self.elb.register_targets(
                TargetGroupArn=target_group_arn,
                Targets=targets)
            log('success', "Targets registered in target group.")

            # Create the listener
            listeners = self.elb.create_listener(
                LoadBalancerArn=load_balancer_arn,
                Protocol='HTTPS',
                Port=443,
                Certificates=[{'CertificateArn': certificate_arn}],
                DefaultActions=[{
                    'Type': 'forward',
                    'TargetGroupArn': target_group_arn
                }])
            listener_arn = listeners['Listeners'][0]['ListenerArn']
            self.state_dict['listener_arn'] = listener_arn
            log('success', "Listener created with ARN '%s'." % listener_arn)

            # Indique la zone DNS du Load Balancer
            log('info', "Load balancer up and running. It's DNS name is : %s." % load_balancer_dnsname)

        def generate_config():
            # Generate the config file
            cms_config['core_services'] = {
                "LogService": [
                    [main_instance_ip, 29000]
                ],
                "ResourceService": (
                    [[main_instance_ip, 28000]]
                    + [[ip, 28000] for ip in workers_instance_ips]
                    + [[ip, 28000] for ip in cws1_instance_ips]
                    + [[ip, 28000] for ip in cws2_instance_ips]
                ),
                "ScoringService": [[main_instance_ip, 28500]],
                "Checker": [[main_instance_ip, 22000]],
                "EvaluationService": [[main_instance_ip, 25000]],
                "Worker": [
                    [ip, 26000 + shard]
                    for ip in workers_instance_ips
                    for shard in range(nb_workers_per_instance)
                ],
                "ContestWebServer": (
                    [[ip, 21000 + shard] for ip in cws1_instance_ips for shard in range(nb_cws_per_instance)]
                    + [[ip, 21000 + shard] for ip in cws2_instance_ips for shard in range(nb_cws_per_instance)]
                ),
                "AdminWebServer": [[main_instance_ip, 21100]],
                "ProxyService": [[main_instance_ip, 28600]],
                "PrintingService": [[main_instance_ip, 25123]]
            }
            cms_config['other_services'] = {
                "TestFileCacher": [[main_instance_ip, 27501]]
            }
            # cms_config['contest_listen_address'] = [""] * (nb_cws_per_instance * nb_cws_instances)
            cms_config['contest_listen_address'] = (
                [ip for ip in cws1_instance_ips for _ in range(nb_cws_per_instance)]
                + [ip for ip in cws2_instance_ips for _ in range(nb_cws_per_instance)]
            )
            cms_config['contest_listen_port'] = list(
                9000 + i for i in range(nb_cws_per_instance * nb_cws_instances))
            cms_config['num_proxies_used'] = 1
            cms_config['admin_listen_port'] = 13800
            config_generator = CmsConf.Generator()
            config_generator.create_config_files(**cms_config)
            log('success', 'CMS config files generated.')

        try:
            if config_phase:
                generate_config()
            else:
                up_ec2()
                self.save_to_file()
                up_lb()
            self.save_to_file()

        except Exception as e:
            log('critical', 'An exception happened: %s.' % str(e))
            log('critical', 'Rolling back...')

            self.down()

            # Exitting
            log('critical', 'Aborting.')
            exit(1)

    def down(self):
        # Load the configuration from file if the state dict is empty
        if len(self.state_dict) == 0:
            self.load_from_file(force=True)

        # Terminate the instances
        instances_ids = []
        if 'worker_instances_ids' in self.state_dict:
            try:
                worker_instances_ids = self.state_dict['worker_instances_ids']
                instances_ids += worker_instances_ids
                self.ec2r.instances.filter(InstanceIds=worker_instances_ids).terminate()
                log('info', "Worker instances deleted.")
                del self.state_dict['worker_instances_ids']
            except Exception as e:
                log('danger', "Can't terminate main instance: %s" % e)
        if 'cws1_instances_ids' in self.state_dict:
            try:
                cws1_instances_ids = self.state_dict['cws1_instances_ids']
                instances_ids += cws1_instances_ids
                self.ec2r.instances.filter(InstanceIds=cws1_instances_ids).terminate()
                log('info', "CWS #1 instances deleted.")
                del self.state_dict['cws1_instances_ids']
            except Exception as e:
                log('danger', "Can't terminate CWS #1 instances: %s" % e)
        if 'cws2_instances_ids' in self.state_dict:
            try:
                cws2_instances_ids = self.state_dict['cws2_instances_ids']
                instances_ids += cws2_instances_ids
                self.ec2r.instances.filter(InstanceIds=cws2_instances_ids).terminate()
                log('info', "CWS #2 instances deleted.")
                del self.state_dict['cws2_instances_ids']
            except Exception as e:
                log('danger', "Can't terminate CWS #2 instances: %s" % e)
        if 'main_instance_id' in self.state_dict:
            try:
                main_instance_id = self.state_dict['main_instance_id']
                instances_ids += [main_instance_id]
                self.ec2r.instances.filter(InstanceIds=[main_instance_id]).terminate()
                log('info', "Main instance deleted.")
                del self.state_dict['main_instance_id']
            except Exception as e:
                log('danger', "Can't terminate worker instances: %s" % e)

        # Wait until all the instances are terminated
        if len(instances_ids) > 0:
            try:
                log('info', 'Waiting for the instances to terminate...')
                waiter = self.ec2c.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=instances_ids)
                log('info', 'All the instances are terminated.')
                del self.state_dict['main_instance_ip']
                del self.state_dict['workers_instance_ips']
                del self.state_dict['cws1_instance_ips']
                del self.state_dict['cws2_instance_ips']
                del self.state_dict['instances_ips']
            except Exception as e:
                log('danger', "Can't wait until instances terminate: %s" % e)

        # Delete the load balancer listener
        if 'listener_arn' in self.state_dict:
            listener_arn = self.state_dict['listener_arn']
            try:
                self.elb.delete_listener(ListenerArn=listener_arn)
                log('info', "Load balancer listener '%s' deleted." % listener_arn)
                del self.state_dict['listener_arn']
            except Exception as e:
                log('warning', "Can't delete the load balancer listener '%s': %s" % (listener_arn, e))

        # Delete the load balancer
        if 'load_balancer_arn' in self.state_dict:
            load_balancer_arn = self.state_dict['load_balancer_arn']
            try:
                self.elb.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
                log('info', "Load balancer '%s' deleted." % load_balancer_arn)
                del self.state_dict['load_balancer_arn']
                del self.state_dict['load_balancer_dnsname']
            except Exception as e:
                log('warning', "Can't delete the load balancer '%s': %s" % (load_balancer_arn, e))

        # Delete the target group
        if 'target_group_arn' in self.state_dict:
            target_group_arn = self.state_dict['target_group_arn']
            try:
                self.elb.delete_target_group(TargetGroupArn=target_group_arn)
                log('info', "LB target group '%s' deleted." % target_group_arn)
                del self.state_dict['target_group_arn']
            except Exception as e:
                log('warning', "Can't delete the LB target group '%s': %s" % (target_group_arn, e))

        # Delete the LB security group
        if 'lb_security_group_id' in self.state_dict:
            lb_security_group_id = self.state_dict['lb_security_group_id']

            # Delete LB network interfaces
            lb_network_interfaces_ids = [ni['NetworkInterfaceId'] for ni in (
                self.ec2c.describe_network_interfaces(
                    Filters=[{'Name': 'group-id', 'Values': [lb_security_group_id]}]
                )['NetworkInterfaces'])]
            print('lb_network_interfaces_ids', lb_network_interfaces_ids)
            for lb_network_interfaces_id in lb_network_interfaces_ids:
                try:
                    network_interface = self.ec2r.NetworkInterface(lb_network_interfaces_id)
                    network_interface.delete()
                    log('info', "LB network interface '%s' deleted." % lb_network_interfaces_id)
                except Exception as e:
                    log('warning', "Can't delete the LB network interface '%s': %s"
                        % (lb_network_interfaces_id, e))
            import time
            time.sleep(10)

            try:
                self.ec2c.delete_security_group(GroupId=lb_security_group_id)
                log('info', "LB security group '%s' deleted." % lb_security_group_id)
                del self.state_dict['lb_security_group_id']
            except Exception as e:
                log('warning', "Can't delete the LB security group '%s': %s" % (lb_security_group_id, e))

        # Delete the security group
        if 'security_group_id' in self.state_dict:
            security_group_id = self.state_dict['security_group_id']
            try:
                self.ec2c.delete_security_group(GroupId=security_group_id)
                log('info', "Security group '%s' deleted." % security_group_id)
                del self.state_dict['security_group_id']
            except Exception as e:
                log('warning', "Can't delete the security group '%s': %s" % (security_group_id, e))

        # Delete the main subnet
        if 'main_subnet_id' in self.state_dict:
            main_subnet_id = self.state_dict['main_subnet_id']
            try:
                self.ec2c.delete_subnet(SubnetId=main_subnet_id)
                log('info', "Main subnet '%s' deleted." % main_subnet_id)
                del self.state_dict['main_subnet_id']
                del self.state_dict['main_route_table_association_id']
            except Exception as e:
                log('warning', "Can't delete the main subnet '%s': %s" % (main_subnet_id, e))

        # Delete the cws 1 subnet
        if 'cws1_subnet_id' in self.state_dict:
            cws1_subnet_id = self.state_dict['cws1_subnet_id']
            try:
                self.ec2c.delete_subnet(SubnetId=cws1_subnet_id)
                log('info', "Subnet CWS #1 '%s' deleted." % cws1_subnet_id)
                del self.state_dict['cws1_subnet_id']
                del self.state_dict['cws1_route_table_association_id']
            except Exception as e:
                log('warning', "Can't delete the CWS #1 subnet '%s': %s" % (cws1_subnet_id, e))

        # Delete the cws 2 subnet
        if 'cws2_subnet_id' in self.state_dict:
            cws2_subnet_id = self.state_dict['cws2_subnet_id']
            try:
                self.ec2c.delete_subnet(SubnetId=cws2_subnet_id)
                log('info', "Subnet CWS #2 '%s' deleted." % cws2_subnet_id)
                del self.state_dict['cws2_subnet_id']
                del self.state_dict['cws2_route_table_association_id']
            except Exception as e:
                log('warning', "Can't delete the CWS #2 subnet '%s': %s" % (cws2_subnet_id, e))

        # Delete the main subnet route table
        if 'main_route_table_id' in self.state_dict:
            main_route_table_id = self.state_dict['main_route_table_id']
            try:
                main_route_table = self.ec2r.RouteTable(main_route_table_id)
                main_route_table.delete()
                log('info', "Main subnet route table '%s' deleted." % main_route_table_id)
                del self.state_dict['main_route_table_id']
            except Exception as e:
                log('warning', "Can't delete the main subnet route table '%s': %s"
                    % (main_route_table_id, e))

        # Delete the cws1 subnet route table
        if 'cws1_route_table_id' in self.state_dict:
            cws1_route_table_id = self.state_dict['cws1_route_table_id']
            try:
                cws1_route_table = self.ec2r.RouteTable(cws1_route_table_id)
                cws1_route_table.delete()
                log('info', "CWS #1 subnet route table '%s' deleted." % cws1_route_table_id)
                del self.state_dict['cws1_route_table_id']
            except Exception as e:
                log('warning', "Can't delete the CWS #1 subnet route table '%s': %s"
                    % (cws1_route_table_id, e))

        # Delete the cws2 subnet route table
        if 'cws2_route_table_id' in self.state_dict:
            cws2_route_table_id = self.state_dict['cws2_route_table_id']
            try:
                cws2_route_table = self.ec2r.RouteTable(cws2_route_table_id)
                cws2_route_table.delete()
                log('info', "CWS #2 subnet route table '%s' deleted." % cws2_route_table_id)
                del self.state_dict['cws2_route_table_id']
            except Exception as e:
                log('warning', "Can't delete the CWS #2 subnet route table '%s': %s"
                    % (cws2_route_table_id, e))

        # Delete the Internet gateway
        if 'gateway_id' in self.state_dict and 'vpc_id' in self.state_dict:
            vpc_id = self.state_dict['vpc_id']
            gateway_id = self.state_dict['gateway_id']
            try:
                gateway = self.ec2r.InternetGateway(gateway_id)
                gateway.detach_from_vpc(VpcId=vpc_id)
                log('info', "Internet gateway '%s' detached from VPC '%s'."
                    % (gateway_id, vpc_id))
                gateway.delete()
                log('info', "Internet gateway '%s' deleted." % gateway_id)
                del self.state_dict['gateway_id']
            except Exception as e:
                log('warning', "Can't delete the Internet gateway '%s': %s" % (gateway_id, e))

        # Delete the VPC
        if 'vpc_id' in self.state_dict:
            vpc_id = self.state_dict['vpc_id']
            try:
                self.ec2c.delete_vpc(VpcId=vpc_id)
                log('info', "VPC '%s' deleted." % vpc_id)
                del self.state_dict['vpc_id']
            except Exception as e:
                log('warning', "Can't delete the VPC '%s': %s" % (vpc_id, e))

        # Delete the keypair
        if 'keypair_name' in self.state_dict:
            keypair_name = self.state_dict['keypair_name']
            try:
                key_pair = self.ec2r.KeyPair(keypair_name)
                key_pair.delete()
                log('info', "Keypair '%s' deleted." % keypair_name)
                del self.state_dict['keypair_name']
                os.remove(keypair_name + '.pem')
            except Exception as e:
                log('warning', "Can't delete the keypair '%s': %s" % (keypair_name, e))

        # Save the new configuration
        self.save_to_file()

    def load_from_file(self, force=False):
        if len(self.state_dict) > 0 and not force:
            if input("Current configuration isn't empty. Override? [y/N]").lower() \
                    in ['', 'n', 'no']:
                log('warning', 'Load cancelled cancelled.')
                return
        self.state_dict = {}
        with open(self.id + '.json', 'r+') as f:
            self.state_dict = json.load(f)
            log('info', "Configuration loaded from '%s.json'." % self.id)

    def save_to_file(self):
        with open(self.id + '.json', 'w') as f:
            json.dump(self.state_dict, f)
            log('info', "Configuration saved to '%s.json'." % self.id)
