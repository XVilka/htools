#!/usr/bin/python

# IDA Sync Server Command Line Database Management Utility
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

import os
import sys

sys.path.append("support")
sys.path.append("modules")

import MySQLdb as db
from server_constants import *

# import any available modules.
for file in os.listdir("modules"):
    if file.endswith(".py"):
        file = file.split(".")[0]
        exec("from " + file + " import *")

try:
    module = sys.argv[1]
    cmd    = sys.argv[2]
    
    if cmd in ("create", "drop", "dump"):
        project = sys.argv[3]
except:
    print "usage: dbs <module> [list] [<create|drop|dump> <proj>]" 
    sys.exit(1)

_db = db.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME)
cursor = _db.cursor()
### LIST ###############################################################################################################
if cmd == "list":
    print "views:",


    cursor.execute("SELECT * FROM projects")
    for one in cursor.fetchall():
        print one[1]

### CREATE / DROP ######################################################################################################    
elif cmd in ("create", "drop"):
    print "%s view: %s" % (cmd, project)

    # ensure the requested module is available..
    module_found = False

    for file in os.listdir("modules"):
        if file.endswith(".py"):
            if file == module + ".py":
                module_found = True

    if not module_found:
        print "module: %s, not found." % module
        sys.exit(1)
    
    exec("module = %s()" % module)
    exec("module.%s(\"%s\")" % (cmd, project))
    
### DUMP ###############################################################################################################
elif cmd == "dump":
    print "dumping view of %s" % project

    for row in db.view(project):
        if module == "ida_sync":
            if type in (server_constants.NAME, server_constants.STACK_NAME):
                data = row.data.split("*")[0]
            else:
                data = row.data

            print "%d:::%08x:::%s:::%08x:::%s" % (row.type, row.address, data, row.timestamp, row.user)
