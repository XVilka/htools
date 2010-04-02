# IDA Sync Server Error Handling Class
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

class serverx:
    ############################################################################
    ### constructor
    ###
    ### args:    detailed message describing error.
    ### raises:  none.
    ### returns: none.
    ###
    def __init__(self, message):
        self.message = message


    ############################################################################
    ### print wrapper
    ###
    ### called when printing an exception.
    ###
    ### args:    none.
    ### raises:  none.
    ### returns: string containing exception error message.
    ###
    def __str__(self):
        return self.message


    ############################################################################
    ### msg()
    ###
    ### args:    none.
    ### raises:  none.
    ### returns: string containing exception error message.
    ###
    def msg(self):
        return self.message
