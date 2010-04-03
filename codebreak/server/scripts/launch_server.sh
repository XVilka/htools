#!/bin/sh

#the CLASSPATH should already be setup in the jar file, if not
#you can try something like:
#CLASSPATH=mysql-connector-java-5.1.6-bin.jar:postgresql-8.2-506.jdbc3.jar
#java -classpath $CLASSPATH -jar codebreak_server.jar $1 > /dev/null 2>&1 < /dev/null &

#or even execute the class files directly:
#java codebreak.server.CodeBreakServer codebreak/server/conf/example_server.conf

java -jar codebreak_server.jar server.conf > /dev/null 2>&1 < /dev/null &

