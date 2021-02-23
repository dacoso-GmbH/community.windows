#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021 Sebastian Gruber (@sgruber94) ,dacoso GmbH All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_certificationauthority_configure
short_description: Installs and Configure Windows CA on windows hosts.
author:
- Boris Birneder (@borris70)
- Sebastian Gruber (@sgruber94)
description:
- The C(win_certificationauthority_configure) module Installs and Configure Windows CA on a windows hosts.
requirements:
- needs DomainAdmin rights
- windows feature required : RSAT-AD-PowerShell
options:
  mode:
    description:
      - Is used to install/uninstall Windows Certificate Authority on Server
    choices: [ install, uninstall ]
    default: install
    type: str
  certauthname:
    description:
      - Specify Root CA Name
    type: str
    required: yes
    aliases:
      - caname
  cname:
    description:
      - Specify DNS Alias for Webaccess, CRL and AIA Location
    type: str
    default: "pki"
  keylength:
    description:
      - Specify Key Length from Root Cert
    choices: [ 2048,4096,8192 ]
    default: 4096
    type: int
  validyears:
    description:
      - Specify Root Cert Validity
    type: int
    default: 15
  hash:
    description:
      - Specify Hash Type Root Cert
    choices: [ SHA1,SHA256,SHA384,SHA512 ]
    default: SHA512
    type: str
  domaincontroller:
    description:
      - Specify defines Active Directory Domaincontroller
    type: str
    aliases:
      - dc
    required: yes
'''

EXAMPLES = r'''
- name: Install Windows CA and configure
    win_certificationauthority_configure:
      mode: install
      certauthname: "AD CA"
      cname: "pki"
      keylength: 4096
      validyears: 15
      hash: SHA512
      log_path: C:\logs\ansible_winca.txt

- name: Remove CA ( only for testing purpose - Restart Computer)
    win_certificationauthority_configure:
      mode: uninstall
      caname: "AD CA"
      log_path: C:\logs\ansible_winca.txt
'''
