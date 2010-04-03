#!/bin/sh

#take care of people having different versions of the JDBC connectors
#the jar manifest needs the correct file names

SQLJAR=`ls *mysql*.jar 2>/dev/null`
POSTGRESJAR=`ls *postgres*.jar 2>/dev/null`
MYCP="$SQLJAR $POSTGRESJAR"

echo "Using these JDBC connectors:$MYCP"
cd ..

#create the manifest files 
echo "Main-Class: codebreak.server.CodeBreakServer" > conf/server_manifest.mf
echo "Class-Path: $MYCP" >> conf/server_manifest.mf
echo "Name: codebreak/server/CodeBreakServer/" >> conf/server_manifest.mf
echo "Specification-Title: Code Break Server" >> conf/server_manifest.mf
echo "Specification-Version: 0.0.1" >> conf/server_manifest.mf
echo "Specification-Vendor: XVilka & Nothize." >> conf/server_manifest.mf
echo "Implementation-Title: Code Break Server" >> conf/server_manifest.mf
echo "Implementation-Version: 0.0.1" >> conf/server_manifest.mf
echo "Implementation-Vendor: XVilka & Nothize" >> conf/server_manifest.mf
echo "Implementation-URL: and-developers.com" >> conf/server_manifest.mf

echo "Main-Class: codebreak.server.ServerManager" > conf/manager_manifest.mf
echo "Class-Path: $MYCP" >> conf/manager_manifest.mf
echo "Name: codebreak/server/CodeBreakServer/" >> conf/manager_manifest.mf
echo "Specification-Title: Code Break Server" >> conf/manager_manifest.mf
echo "Specification-Version: 0.0.1" >> conf/manager_manifest.mf
echo "Specification-Vendor: XVilka & Nothize." >> conf/manager_manifest.mf
echo "Implementation-Title: Code Break Server" >> conf/manager_manifest.mf
echo "Implementation-Version: 0.0.1" >> conf/manager_manifest.mf
echo "Implementation-Vendor: XVilka & Nothize" >> conf/manager_manifest.mf
echo "Implementation-URL: and-developers.com" >> conf/manager_manifest.mf

#build the jar files
javac *.java

jar cfm codebreak_server.jar conf/server_manifest.mf *.class
mv -f codebreak_server.jar out/

jar cfm codebreak_manager.jar conf/manager_manifest.mf *.class
mv -f codebreak_manager.jar out/

rm -f *.class
