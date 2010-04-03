#!/bin/sh

#the CLASSPATH should already be setup in the jar file, if not
#you can try something like:
#CLASSPATH=mysql-connector-java-5.1.6-bin.jar:postgresql-8.2-506.jdbc3.jar
#java -classpath $CLASSPATH -jar codebreak_manager.jar $1

java -jar codebreak_manager.jar server.conf

