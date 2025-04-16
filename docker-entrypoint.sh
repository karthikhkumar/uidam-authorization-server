#!/bin/bash

#
# Copyright (c) 2023 - 2024 Harman International
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
#

#Allow overriding default timezone using environment variable
if [ -n "${TZ}" ]; then
  ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime
  echo ${TZ} > /etc/timezone
fi

#jks configuration
base64 -d /etc/uidam/keystore/jks-file > /app/${KEYSTORE_FILE_NAME}

#copy public and private key files
cp /etc/uidam/cert/* /app

#custom ui
#if exist 3rd party customizations tgz file, extract it, otherwise use default customizations for login
echo Starting custom ui changes...
file=/tmp/uidamCustomUI/uidamCustomUI.tgz
tmpCustomUIPath=/tmp/customui
if [ -f $file ]; then
    cd $tmpCustomUIPath
    tar --wildcards --overwrite --strip-components=1 -xf $file
    cd /app

   echo "Deployed all new UI files"
	fi

# Start Tomcat process
echo Starting microservice...
exec java $JAVA_OPTS -Dconfig.dir=/app/config/ -Dproperties.file=application.yml -Dproperties.file=external-idp-application.yml -jar *.jar "$@"
