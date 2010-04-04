/*
    Code Break DataBase Interface
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>
    Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>
    Copyright (C) 2010 XVilka <xvilka at gmail d0t com>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation; either version 2 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA
*/

package codebreak.admin;

import codebreak.server.CodeBreakAdmin;
import codebreak.server.CodeBreakConstants;

import java.sql.*;
import java.util.Properties;


/**
 * DB_Interface
 * This class offers various utility functions used by the servlet
 */

class DB_Interface implements CodeBreakConstants {

    /**
     * getJDBCConnection sets up and returns a JDBC connection
     *
     * @param sm
     * @return a JDBC connection
     */
    protected static Connection getJDBCConnection(CodeBreakAdmin sm) {
        Connection con = null;
        Properties props = sm.getProps();
        String driver = props.getProperty("JDBC_DRIVER", "org.postgresql.Driver");
        try {
            Class.forName(driver);
            if (driver.indexOf("mysql") != -1) {
                sm.setuseMysql(true);
            }
        } catch (ClassNotFoundException e) {
            System.err.println("ClassNotFoundException: " + e.getMessage());
            System.err.println("you need the jdbc jar for " + driver + " in your classpath!\n");
            System.err.println("Current classpath is: ");
            System.err.println(System.getProperty("java.class.path"));
            e.printStackTrace();
            return null;
        }

        try {
            String userid = props.getProperty("DB_USER", "codebreak");
            String password = props.getProperty("DB_PASS");
            if (password == null) {
                //need to prompt for the password
            }
            String url = props.getProperty("JDBC_URL");
            if (url == null) {
                String dbname = props.getProperty("DB_NAME", "codebreak");
                String host = props.getProperty("DB_HOST", "127.0.0.1");
                String ssl = props.getProperty("USE_SSL", "no");
                String dbtype = props.getProperty("JDBC_NAME", "postgresql");
                url = "jdbc:" + dbtype + "://" + host + "/" + dbname;
                if (ssl.equalsIgnoreCase("yes")) {
                    url += "?ssl";
                }
            }
            con = DriverManager.getConnection(url, userid, password);
        } catch (SQLException ex) {
            System.err.println("SQLException: " + ex.getMessage());
            System.err.println("check permissions in your database configuration file\n");
            return null;
        }
        try {
            DatabaseMetaData meta = con.getMetaData();
            System.out.println("Connected to " + meta.getURL());
            System.out.print("DB Driver : " + meta.getDriverName());
            System.out.println(" v: " + meta.getDriverVersion());
            System.out.println("Database: " + meta.getDatabaseProductName() + " "
                    + meta.getDatabaseMajorVersion() + "." + meta.getDatabaseMinorVersion());
            System.out.println("JDBC v: " + meta.getJDBCMajorVersion() + "." + meta.getJDBCMinorVersion());
        } catch (Exception ex1) {
            System.err.println("Couldn't get driver metadata: " + ex1.getMessage());
            //Is this a fatal error, do you want to close con here?
        }
        return con;
    }


    /**
     * runInsertInt is a database insert helper function, it runs an insert and returns
     * a Int value based on the result of the query - Statements must return a value to
     * be used with this function
     *
     * @param s a prepared statement that provides a return value
     * @return integer return of the insert query
     */
    protected static int runInsertInt(PreparedStatement s) {
        int rval = -1;
        try {
            ResultSet rs = s.executeQuery();
            if (rs.next()) {
                rval = rs.getInt(1);
                //System.out.println("SQL Insert rval:  " + rval);
            }
            rs.close();
        } catch (SQLException e) {
            System.err.println("SQL Exception encountered");
            System.err.println(e);
        } catch (Exception exc) {
            System.err.println("Database Insert error: " + exc.getMessage());
            //            exc.printStackTrace();
        }
        return rval;
    }


    /**
     * runInsertLong is a database insert helper function, it runs an insert and returns
     * a Long value based on the result of the query - Statements must return a value to
     * be used with this function
     *
     * @param s a prepared statement that provides a return value
     * @return long return of the insert query
     */
    protected static long runInsertLong(PreparedStatement s) {
        long rval = -1;
        try {
            ResultSet rs = s.executeQuery();
            if (rs.next()) {
                rval = rs.getLong(1);
                System.out.println("SQL Insert rval:  " + rval);
            }
            rs.close();
        } catch (SQLException e) {
            System.err.println("SQL Exception encountered");
            System.err.println(e);
        } catch (Exception exc) {
            System.err.println("Database Insert error: " + exc.getMessage());
            exc.printStackTrace();
        }
        return rval;
    }


}