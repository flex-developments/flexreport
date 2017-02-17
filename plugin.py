#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

Modify by Felix Lopez (https://github.com/flex-developments)
'''
from __future__ import with_statement
import sys
import re
import os
from plugins import core
from model import api

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato & Felix Lopez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC... Modify by Felix Lopez"
__credits__ = ["Francisco Amato & Felix Lopez"]
__version__ = "1.0"
__maintainer__ = "Felix Lopez"
__email__ = "flex.developments in gmail.com"
__status__ = "Development"

########################################### Parsing ###########################################
class FLEXReportParser(object):
    def __init__(self, fileReport):
        api.log(
            '[INFO] FLEX Report Plugin: Parsing report...'
            ,level='INFO')

        reportTree = self.parse_xml(fileReport)

        if reportTree:
            self.hosts = [data for data in self.get_hosts(reportTree)]
            self.vulnerabilities = [data for data in self.get_vulnerabilities(reportTree)]
        else:
            self.hosts = []
            self.vulnerabilities = []

    def parse_xml(self, fileReport):
        try:
            reportTree = ET.fromstring(fileReport)
        except SyntaxError, err:
            print('SyntaxError: %s. %s' % (err, fileReport))
            return None

        return reportTree

    def get_hosts(self, reportTree):
        for host in reportTree.find('Hosts'):
            yield Host(host)

    def get_vulnerabilities(self, reportTree):
        for vulnerability in reportTree.find('Vulnerabilities'):
            yield Vulnerability(vulnerability)


class Host(object):
    def __init__(self, host_node):
        self.id = host_node.get('id')
        self.idFaraday = None
        self.ip = host_node.get('ip')
        self.os = host_node.get('os')

        self.interfaces = []
        for interface in host_node.find('HostInterfaces'):
            self.interfaces.append(HostInterface(interface))


class HostInterface(object):
    def __init__(self, interface_node):
        self.id = interface_node.get('id')
        self.idFaraday = None

        self.hostnames = []
        for hostname in interface_node.find('HostNames'):
            self.hostnames.append(hostname.get('hostname'))

        self.services = []
        for service in interface_node.find('HostServices'):
            self.services.append(HostService(service))


class HostService(object):
    def __init__(self, service_node):
        self.id = service_node.get('id')
        self.idFaraday = None
        self.name = service_node.get('name')
        self.protocol = service_node.get('protocol')
        self.version = service_node.get('version')
        self.status = service_node.get('status')

        self.ports = []
        for port in service_node.find('ServicePorts'):
            self.ports.append(port.get('port'))


class Vulnerability(object):
    def __init__(self, vulnerability_node):
        self.id = vulnerability_node.get('id')
        self.type = vulnerability_node.get('type')
        self.severity = vulnerability_node.get('severity')

        self.name = vulnerability_node.find('VulnerabilityName').text
        self.description = vulnerability_node.find('VulnerabilityDescription').text
        self.resolution = vulnerability_node.find('VulnerabilityResolution').text

        self.refs = []
        for ref in vulnerability_node.find('VulnerabilityReferences'):
            self.refs.append(ref.text)

        self.vulnhosts = []
        for vulnhost in vulnerability_node.find('VulnerableHosts'):
            self.vulnhosts.append(VulnerableHost(vulnhost))

        if self.type=='WEB':
            details = vulnerability_node.find('WebVulnerabilityDetails')
            self.vulnerabilityWebSite = (details.find('VulnerabilityWebSite').text if (details.find('VulnerabilityWebSite') is not None) else "")
            self.vulnerabilityPath = (details.find('VulnerabilityPath').text if (details.find('VulnerabilityPath') is not None) else "")
            self.vulnerabilityRequest = (details.find('VulnerabilityRequest').text if (details.find('VulnerabilityRequest') is not None) else "")
            self.vulnerabilityResponse = (details.find('VulnerabilityResponse').text if (details.find('VulnerabilityResponse') is not None) else "")
            self.vulnerabilityParams = (details.find('VulnerabilityParams').text if (details.find('VulnerabilityParams') is not None) else "")
            self.vulnerabilityMethod = (details.find('VulnerabilityMethod').text if (details.find('VulnerabilityMethod') is not None) else "")
            self.vulnerabilityPName = (details.find('VulnerabilityPName').text if (details.find('VulnerabilityPName') is not None) else "")
            self.vulnerabilityQuery = (details.find('VulnerabilityQuery').text if (details.find('VulnerabilityQuery') is not None) else "")
            self.vulnerabilityCategory = (details.find('VulnerabilityCategory').text if (details.find('VulnerabilityCategory') is not None) else "")


class VulnerableHost(object):
    def __init__(self, vulnerablehost_node):
        self.id = vulnerablehost_node.get('id')
        self.subid = vulnerablehost_node.get('subid')

############################################ Plugin ############################################

class FLEXReportPlugin(core.PluginBase):
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "FLEXReport"
        self.name = "FLEX Report Plugin"
        self.plugin_version = "1.0"
        self.version = "1"
        self.framework_version = "1.0"
        self.options = None
        self._current_output = None
        self.target = None
        self._command_regex = re.compile(
            r'^(flexreport|sudo flexreport).*?')

        global current_path
        self._output_file_path = os.path.join(
            self.data_path,
            'flexreport-output-%s.xml' % self._rid)

    def parseOutputString(self, output, debug=False):
        parser = FLEXReportParser(output)

        ###################################### Load Hosts ######################################
        api.log(
            '[INFO] FLEX Report Plugin: Loading hosts...'
            ,level='INFO')
        for host in parser.hosts:
            api.log(
                '[INFO] FLEX Report Plugin: Host <' + host.id + '>'
                ,level='INFO')

            host.idFaraday = self.createAndAddHost(host.ip, os=host.os)

            api.log(
                '[INFO] FLEX Report Plugin: Loading interfaces...'
                ,level='INFO')
            for interface in host.interfaces:
                api.log(
                    '[INFO] FLEX Report Plugin: Interface <' + interface.id + '>'
                    ,level='INFO')

                interface.idFaraday = self.createAndAddInterface(
                    host.idFaraday,
                    host.ip,
                    ipv4_address=host.ip,
                    hostname_resolution=interface.hostnames)

                api.log(
                    '[INFO] FLEX Report Plugin: Loading services...'
                    ,level='INFO')
                for service in interface.services:
                    api.log(
                        '[INFO] FLEX Report Plugin: Service <' + service.id + '>'
                        ,level='INFO')

                    service.idFaraday = self.createAndAddServiceToInterface(
                        host.idFaraday,
                        interface.idFaraday,
                        service.name,
                        service.protocol,
                        ports=service.ports,
                        version=service.version,
                        status=service.status)

        ################################# Load Vulnerabilities #################################
        api.log(
            '[INFO] FLEX Report Plugin: Loading vulnerabilities...'
            ,level='INFO')
        for vulnerability in parser.vulnerabilities:
            api.log(
                '[INFO] FLEX Report Plugin: Vulnerability ' + vulnerability.id
                ,level='INFO')

            for vulnhost in vulnerability.vulnhosts:
                api.log(
                    '[INFO] FLEX Report Plugin: Vulnerability ' + vulnerability.id + ' to host ' + vulnhost.id
                    ,level='INFO')

                vulnhost_object = next(host for host in parser.hosts if(host.id == vulnhost.id))

                if not vulnhost_object:
                    api.log(
                        '[ERROR] FLEX Report Plugin: Vulnerable host missing <' + vulnhost.id + '>'
                        ,level='ERROR')

                else:
                    if vulnerability.type=='HOST':
                        self.createAndAddVulnToHost(
                            vulnhost_object.idFaraday,
                            vulnerability.name,
                            desc=vulnerability.description,
                            ref=vulnerability.refs,
                            severity=vulnerability.severity,
                            resolution=vulnerability.resolution)

                    elif vulnerability.type=='SERVICE':
                        service_object = None
                        for interace_object in vulnhost_object.interfaces:
                            service_object = next(service for service in interace_object.services if(service.id == vulnhost.subid))
                            if service_object: break

                        if not service_object:
                            api.log(
                                '[ERROR] FLEX Report Plugin: Vulnerable host service missing <' + vulnhost.subid + '>'
                                ,level='ERROR')
                        else:
                            self.createAndAddVulnToService(
                                vulnhost_object.idFaraday,
                                service_object.idFaraday,
                                vulnerability.name,
                                desc=vulnerability.description,
                                ref=vulnerability.refs,
                                severity=vulnerability.severity,
                                resolution=vulnerability.resolution)

                    elif vulnerability.type=='WEB':
                        service_object = None
                        for interace_object in vulnhost_object.interfaces:
                            service_object = next(service for service in interace_object.services if(service.id == vulnhost.subid))
                            if service_object: break

                        if not service_object:
                            api.log(
                                '[ERROR] FLEX Report Plugin: Vulnerable host service missing <' + vulnhost.subid + '>'
                                ,level='ERROR')
                        else:
                            self.createAndAddVulnWebToService(
                                vulnhost_object.idFaraday,
                                service_object.idFaraday,
                                vulnerability.name,
                                desc=vulnerability.description,
                                ref=vulnerability.refs,
                                severity=vulnerability.severity,
                                resolution=vulnerability.resolution,
                                website=vulnerability.vulnerabilityWebSite,
                                path=vulnerability.vulnerabilityPath,
                                request=vulnerability.vulnerabilityRequest,
                                response=vulnerability.vulnerabilityResponse,
                                method=vulnerability.vulnerabilityMethod,
                                pname=vulnerability.vulnerabilityPName,
                                params=vulnerability.vulnerabilityParams,
                                query=vulnerability.vulnerabilityQuery,
                                category=vulnerability.vulnerabilityCategory)
                    else:
                        api.log(
                            '[ERROR] FLEX Report Plugin: Vulnerability Type unknown ' + self.type
                            ,level='ERROR')
        del parser

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass


def createPlugin():
    return FLEXReportPlugin()

if __name__ == '__main__':
    parser = FLEXReportParser(sys.argv[1])
    for host in parser.hosts:
        print host.ip