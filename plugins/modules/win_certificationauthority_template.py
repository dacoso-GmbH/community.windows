#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021 Sebastian Gruber (sgruber94) ,dacoso GmbH All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_certificationauthority_template
short_description: Duplicate or query Windows CA Templates
author:
- Boris Birneder (@borris70)
- Sebastian Gruber (@sgruber94)
description:
- The C(wwin_certificationauthority_template) manages Windows CA Templates on windows hosts.
requirements:
- needs DomainAdmin rights
- windows feature required : RSAT-AD-PowerShell
options:
  mode:
    description:
      - Is used to manage or query Windows Certificate Authority on Server
    choices: [ query, manage ]
    default: manage
    type: str
  originaltemplate:
    description:
      - Specify original Source Templatename to duplicate
      - Required if l(mode=manage), otherwise ignored.
    type: str
  newtemplatename:
    description:
      - Specify new duplicated template Name
      - DNS Alias for Webaccess, CRL and AIA Location
      - Required if l(mode=manage), otherwise ignored.
    type: str
    required: yes
  newkeylength:
    description:
      - Specify new KeyLength for new CA Template
      - Required if l(mode=manage), otherwise ignored.
    choices: [ 2048,4096,8192 ]
    default: 4096
    type: int
  autoenrollment:
    description:
      - Specify for a AD Group read and enroll and autoenrollment rights
      - Required if l(mode=manage), otherwise ignored.
    type: str
    default: no
  publishad:
    description:
      - Specify if Certificates should be published to ActiveDirectory
      - Required if l(mode=manage), otherwise ignored.
    type: bool
    default: no
  validyears:
    description:
      - Specify Certificate Validity between one(1) and five(5) years
      - Required if l(mode=manage), otherwise ignored.
    type: int
    default: 1
  domaincontroller:
    description:
      - Specify defines Active Directory Domaincontroller Hostname ( Schema Master)
    type: str
    aliases:
      - dc
    required: yes
'''

EXAMPLES = r'''
- name: Manage Certification Authority Templates
    win_certificationauthority_template:
      mode: manage
      originaltemplate: "Webserver"
      newtemplatename: "myWebserver"
      newkeylength: 4096
      validyears: 1
      publishad: yes
      enrollment:  enrollmentGroup
      autoenrollment: myautoenrollmentGroup
      domaincontroller: dc01
      log_path: "C:\logs\ansible_winca.txt"

- name: Query Certification Authority Templates
    win_certificationauthority_template:
      mode: query
'''
