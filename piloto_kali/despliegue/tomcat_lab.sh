#!/bin/sh
set -eu
cp -a /usr/local/tomcat/webapps.dist/manager /usr/local/tomcat/webapps/
# El manager solo puede alcanzarse desde el puente interno, sin puertos publicados.
cat > /usr/local/tomcat/webapps/manager/META-INF/context.xml <<XML
<Context privileged="true" antiResourceLocking="false">
  <Valve className="org.apache.catalina.valves.RemoteCIDRValve" allow="192.168.57.0/24" />
</Context>
XML
cat > /usr/local/tomcat/conf/tomcat-users.xml <<XML
<tomcat-users><role rolename="manager-gui"/><user username="labuser" password="$LAB_TARGET_PASSWORD" roles="manager-gui"/></tomcat-users>
XML
exec catalina.sh run
