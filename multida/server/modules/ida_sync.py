# IDA Multida Server Module
# Copyright (C) 2005 Pedram Amini <pedram.amini@gmail.com>
# Copyright (C) 2010 Jiri Suchan <yed@vanyli.net>
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

import time
import MySQLdb as db

from serverx          import *
from server_constants import *

class ida_sync(object):
    ############################################################################
    ### constructor
    ###
    ### args:    none.
    ### raises:  none.
    ### returns: none.
    ###
    def __init__(self):
        '''
        open the IDA Sync database, creating it if it doesn't exist.
        '''

        self.db = db.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME)
        self.cursor = self.db.cursor()

        self.cursor.execute("SHOW TABLES LIKE \"project\"")

        if not self.cursor.fetchone():
            self.cursor.execute("""
                CREATE TABLE project (
                    `id` int(5) auto_increment,
                    `name` varchar(50),
                    PRIMARY KEY (`id`)

                )
                """)

            self.cursor.execute("""
                CREATE TABLE record (
                    `id` int(9) auto_increment,
                    `project_id` int(5),
                    `user_id`   int(5),
                    `teatime`   timestamp,
                    `address`   varchar(20),
                    `type`      int(5),
                    `data`      text,
                    `start`     varchar(20),

                    PRIMARY KEY (`id`),
                    CONSTRAINT `projectid_to_project` FOREIGN KEY (`project_id`) REFERENCES `project` (`id`),
                    CONSTRAINT `userid_to_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)

                    )
                """)
        # if it doesn't already exist, define a view to track user updates.
        #description = "__last__[username:S,project:S,timestamp:L]"

    def last_view(self, username=None, project=None):
        '''
        returns user's last records from project
        '''

        if not username:
            username = self.username

        if not project:
            project = self.project

        self.cursor.execute("""
            SELECT *
            FROM
                record
            LEFT JOIN
                users ON users.id = record.user_id
            LEFT JOIN
                project ON project.id = record.project_id
            WHERE
                users.username = '%s'
            AND
                project.name = '%s'
            ORDER BY
                record.id DESC
            LIMIT 1""" % (username, project))

        return self.cursor.fetchone()

    ############################################################################
    ### _init()
    ###
    ### args:    s           - connected socket.
    ###          connections - global list of connection records.
    ###          connection  - current connection record.
    ###          project     - requested project.
    ###          username    -
    ###          password    -
    ### raises:  exception on error.
    ### returns: none.
    ### notes:   generated exceptions should not close the socket. the calling
    ###          thread handler will relay the error message back to the client
    ###          and then close the socket.
    ###
    def _init(self, s, connections, connection, project, username, password):
        self.sock        = s
        self.connections = connections
        self.connection  = connection
        self.project     = project
        self.username    = username
        self.password    = password

        # create an exception if the view doesn't exist.
        if not self._findproject(self.project):
            raise serverx("requested project not found.")

        # determine the user's last update.
        index = self.last_view()

        if index:
            last = index[3] #timestamp

            # refresh the last update record.
            self.update_last()
        else:
            last = 0

        print ">>DEBUG %08x" % last

        # locate all changes made since the user's last update.
        #index   = self.proj_view.filter(lambda row: row.timestamp >= last)
        subview = self._get_from(last)

        # XXX - this is a cheap hack because the IDA plugin doesn't seem to
        # process the first message.
        self.sock.sendall("31337:::deadbeef:::sync")

        for record in subview:
            msg = "%d:::%08x:::%s" % (record.type, record.address, record.data)
            try:
                self.sock.sendall(msg)
                self.sock.recv(1)
            except:
                break

        # reset the last update time.
        self.update_last()

    def _get_from(self, index=None, address=None, start=None):

        q = """
            SELECT *
            FROM
                record AS r
            LEFT JOIN project AS p
                ON p.id = r.project_id
            LEFT JOIN users AS u
                ON u.id = r.user_id
            WHERE
                p.name = '%s'
            AND
                u.username = '%s'
            """ % (self.project, self.username)

        if index:
            q += ' AND r.id = %d' % index

        if address:
            q += ' AND r.address = %s' % address

        if start:
            q += ' AND r.start = %s' % start

        if start or address or index:
            return self.cursor.fetchone()

        else:
            self.cursor.execute(q)
            return self.cursor.fetchall()

    def _findproject(self, project):
        if not project.isalpha():
            raise serverx("project name can containts only alpha character")

        result = self.cursor.execute("SELECT * FROM project WHERE name = \"%s\"" % project)

        if not result:
            return None

        return result


    def create(self, project):
        '''
        creates project
        '''
        if self._findproject(project):
            raise serverx("project '%s' already exists" % project)

        self.cursor.execute("INSERT INTO project VALUES(NULL, \"%s\")" % project)
        #self.db.getas(project + "[type:I,address:L,data:S,timestamp:L,user:S]")


    def delete_row(self, address, type):
        '''
        we can't just search for an exact address/type match because a regular
        comment and a repeatable comment are considered overlapping.
        '''
        start = 0
        while True:
            index = self._get_from(address=address, start=start)
            start = start + 1

            if not index:
                break

            # data types are the same.
            if type == index[5]: # index 5 == type
                self.cursor.execute("""
                DELETE FROM record
                WHERE
                    id = %d
                LIMIT 1
                    """ % (index[0]))

            # data types are both comments.
            if type in (server_constants.REG_COMMENT, server_constants.REP_COMMENT) and \
                row.type in (server_constants.REG_COMMENT, server_constants.REP_COMMENT):
                self.cursor.execute("""
                DELETE FROM record
                WHERE
                    id = %d
                LIMIT 1
                    """ % (index[0]))

    def drop(self, project):
        '''
        drop project and all its records
        '''
        id = self._findproject(project)[0]

        self.cursor.execute("""
            DELETE FROM record
            WHERE project_id = %d """ % id)

        self.cursor.execute("""
            DELETE FROM project WHERE id = %d""" % id)


    def list_projects(self):
        '''
        list all projects
        '''
        self.cursor.execute("SELECT * FROM project")
        return self.cursor.fetchall()


    def list_rows(self, project):
        '''
        list all records
        '''
        self.cursor.execute("SELECT * FROM record")
        return self.cursor.fetchall()


    def reset_last(self, username, project):
        '''
        delete last record
        '''
        index = self.last_view()

        if index:
            self.delete_record(index)


    def run(self):
        '''
        enter an infinite read loop to process all inbound requests.
        '''
        while True:
            try:
                buf = self.sock.recv(1024)
                buf = buf.rstrip("\n")

                if not buf:
                    raise Exception
            except:
                msg = "[!] connection from %s for ida_sync::%s closed." % (self.sock.getpeername()[0], self.project)
                self.sock.close()
                raise serverx(msg)

            # parse out the fields, ignore and continue on error.
            try:
                (type, address, data) = buf.split(":::")

                type    = int(type)
                address = long(address, 16)
            except:
                continue

            # print to console.
            if type in (server_constants.NAME, server_constants.STACK_NAME):
                print_data = data.split("*")[1]
            else:
                print_data = data

            print "[*] data from %s. type %d. @%08x. %s" % (self.username, type, address, print_data)

            # erase any previous overlapping data at this address.
            self.delete_row(address, type)

            # append the received data to the database.
            self.proj_view.append(type      = type,
                                  address   = address,
                                  data      = data,
                                  timestamp = long(time.time()),
                                  user      = self.username)

            # commit changes to database.
            # self.db.commit()

            # walk through all active connections and relay the received data
            # to all equivalent module/project combinations.
            for conn in self.connections:
                # ignore the current connection.
                if conn == self.connection:
                    continue

                if conn[server_constants.MODULE] == "ida_sync" and conn[server_constants.PROJECT] == self.project:
                    conn[server_constants.SOCK].sendall(buf)
                    self.update_last(conn[server_constants.USERNAME], conn[server_constants.PROJECT])


    def update_last(self, username=None, project=None):
        '''
        update last... something
        '''

        username = username or self.username
        project = project or self.project

        index = self.last_view(username, project)

        # if a last update entry already exists for this user, remove it.
        if index:
            self.delete_record(index)

        # create the last update entry.
        self.append_record(username=username, project=project, timestamp = long(time.time()))

    def delete_record(index):
        '''
        deleting record from db
        '''

        #self.cursor.execute("""
        #
        #""" % index

    def append_record(username, project, timestamp):
        '''
        appending record to db
        '''

        self.cursor.execute("""
        #
        #""" % username, project, timestamp
