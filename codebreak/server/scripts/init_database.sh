#!/bin/sh

# these are user configurable - but you should prob them across all aux files # 
SERVICE_NAME=codebreak
CODEBREAK_DB=codebreakDB
CODEBREAK_CONF=server.conf
IDENT="initdb"

# these can also be set via exported environmental variables                  #
# eg:  >INSTALLDIR=/usr/local/codebreak/server                              #
#      >export INSTALLDIR                                                     #
#      >make install                                                          #
# if you do set these via the environment, you should configure your system   #
# to always set them (other scripts depend upon the values of these variables)#
CODEBREAK_SERVER_DIR="${CODEBREAK_SERVER_DIR:-/opt/codebreak/server}"
CODEBREAK_LOG="${CODEBREAK_LOG:-/var/log/codebreak}"
CODEBREAK_SCRIPT="${CODEBREAK_SCRIPT:-/usr/sbin/codebreakctl}"
CODEBREAK_USER="${CODEBREAK_USER:-codebreak}"
CODEBREAK_GROUP="${CODEBREAK_GROUP:-codebreak}"
# end #

# for those that actually use SELinux
if [ -x "/sbin/runuser" ];
then
    SU="/sbin/runuser"
else
    SU="su"
fi

USERADD=`which adduser`

if [ -f "$CODEBREAK_SERVER_DIR/$CODEBREAK_CONF" ]; 
then
   LIKELYDB=`grep ^JDBC_NAME server.conf | grep -o "mysql\|postgresql"`
   echo "According to your installed server.conf file, you want to use: $LIKELYDB"
   echo "(if $LIKELYDB is not correct, you should exit and edit $CODEBREAK_SERVER_DIR/server.conf)"
elif [ -f "$CODEBREAK_CONF" ]; 
then
   LIKELYDB=`grep ^JDBC_NAME server.conf | grep -o "mysql\|postgresql"`
   echo "According to your local server.conf file, you want to use: $LIKELYDB"
   echo "(if $LIKELYDB is not correct, you should exit and edit server.conf)"
else
   LIKELYDB="postgresql"
   echo "Couldn't find your server.conf file, you really should have one..."
fi

echo "Select which database type you would like initialize for use with Code Break"
OPTIONS="MySQL PostgreSQL Exit"
select opt in $OPTIONS; do
   if [ "$opt" = "MySQL" ]; then
    echo "Initializing mysql..."
    echo "The account you are running as must have several mysql create permissions"
    echo "Do you want to continue ?"
     OPTIONS2="yes no"
     select opt2 in $OPTIONS2; do
	if [ "$opt2" = "yes" ]; then
	  echo "adding user $CODEBREAK_USER"
	  $SU -c "$USERADD $CODEBREAK_USER"
	  mysql < my_dbschema.sql 
	  echo "MySQL Code Break initialization done"
	  exit
	elif [ "$opt2" = "no" ]; then
	  exit
	else
	  echo "1 for 'yes' or 2 for 'no'"
	fi
     done
    exit
   elif [ "$opt" = "PostgreSQL" ]; then
    echo "adding user $CODEBREAK_USER"
    $SU -c "$USERADD $CODEBREAK_USER"
    echo "Initializing postgres..."
    #pg_hba.conf defaults to "ident sameuser" so -U doesn't work
    #however to su to users prior to psql commands, $CODEBREAK_USER must exist
    #as a local user....sigh, the follow attemps -U commands, then 
    #falls back to su style commands
    createuser -U postgres -s -d -R $CODEBREAK_USER
    if [ $? -ne 0 ];
    then
       $SU postgres -c "createuser -s -d -R $CODEBREAK_USER"
    fi
    createdb -U $CODEBREAK_USER $CODEBREAK_DB
    if [ $? -ne 0 ];
    then
       $SU $CODEBREAK_USER -c "createdb $CODEBREAK_DB"
    fi
    psql -q -U $CODEBREAK_USER -d $CODEBREAK_DB -f dbschema.sql
    if [ $? -ne 0 ];
    then
       $SU $CODEBREAK_USER -c "psql -q -d $CODEBREAK_DB < dbschema.sql"
    fi
    echo
    echo "Note:"
    echo "failures in the postgres init are usually due to issues"
    echo "with pg_hba.conf or system permissions"
    echo "ie 'ident sameuser' "
    exit
   elif [ "$opt" = "Exit" ]; then
    exit
   else
    echo "only options 1-3 are supported" 
   fi
done

