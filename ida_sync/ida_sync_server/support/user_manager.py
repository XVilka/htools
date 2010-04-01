# IDA Sync Server User Management Class
# Copyright (C) 2005 Pedram Amini <pedram.amini@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307 USA

#import Mk4py as mk
from serverx import *
from server_constants import *
import MySQLdb

################################################################################
### user_manager
###
### this class provides an interface for the general management of users.
###
class user_manager(object):
    ############################################################################
    ### constructor
    ###
    ### args:    none.
    ### raises:  none.
    ### returns: none.
    ###
    def __init__(self):
        # open the users database, creating it if it doesn't exist.
        #self.db = mk.storage("databases/users.db", 1)
        self.db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME)
        self.cursor = self.db.cursor()
        #this doesn't work, dunno why
        #self.cursor.execute("CREATE TABLE IF NOT EXISTS `users` (`id` int(5) auto_increment, `name` varchar(50), `pass` varchar(50), `realname` varchar(50), PRIMARY KEY (`id`))")
        self.cursor.execute("SHOW TABLES LIKE \"users\"")

        if not self.cursor.fetchone():
            self.cursor.execute("CREATE TABLE `users` (`id` int(5) auto_increment, `username` varchar(50), `pass` varchar(50), `realname` varchar(50), PRIMARY KEY (`id`))")



    ############################################################################
    ### add()
    ###
    ### args:    username - unique username to add.
    ###          password - password.
    ###          realname - real name.
    ### raises:  exception on error.
    ### returns: none.
    ###
    def add(self, username, password, realname):
        # ensure the user doesn't already exist.
        if self._finduser(username):
            raise serverx("username already exists")

        self.cursor.execute("INSERT INTO users VALUES(NULL, '%s', '%s', '%s')" % (username, password, realname))


    def _finduser(self, username):
        if not username.isalpha():
            raise serverx("username should containts only alpha characters")

        self.cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
        result = self.cursor.fetchone()
        if result:
            return result
        return None

    ############################################################################
    ### delete()
    ###
    ### args:    username - user to delete.
    ### raises:  exception on error.
    ### returns: none.
    ###
    def delete(self, username):
        # ensure the user exists.

        if not self._finduser(username):
            raise serverx("username not found")

        self.cursor.execute("DELTE FROM users WHERE username = `%s`" % username)


    ############################################################################
    ### list()
    ###
    ### args:    none.
    ### raises:  none.
    ### returns: none.
    ###
    def list(self):
        self.cursor.execute("SELECT * FROM users")
        return self.cursor.fetchall()
        


    ############################################################################
    ### update()
    ###
    ### args:    username - user to update.
    ###          password - new password.
    ###          realname - new value for real name.
    ### raises:  exception on error.
    ### returns: none.
    ###
    def update(self, username, password, realname):

        if not self._finduser(username):
            raise serverx("user not found")

        self.delete(username)
        self.add(username, password, realname)

    ############################################################################
    ### validate()
    ###
    ### args:    username - user to validate as.
    ###          password - username's password.
    ### raises:  exception on error.
    ### returns: none.
    ###
    def validate(self, username, password):
        # ensure the user exists.

        user = self._finduser(username)

        if not user:
            raise serverx("username not found")

        if (user[2] != password):
            raise serverx("invalid username or password")
