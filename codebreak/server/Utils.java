/*
    Code Break Utils
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

package codebreak.server;

import java.io.*;
import java.security.SecureRandom;

/**
 * Utils
 * This class offers various utility functions used by the server
 */

class Utils {

    private static final SecureRandom srand = new SecureRandom();

    /**
     * toHexString - generate a hex string representation of the specified
     * portion of the given array
     *
     * @param data   The array to be converted
     * @param start  The starting index within the array
     * @param length The number of bytes to represent
     * @return The string representation of the given array
     */
    private static String toHexString(byte[] data, int start, int length) {
        String hex = "";
        int end = start + length;
        for (int i = start; i < end; i++) {
            //need to ensure that we have a leading zero for bytes < 0x10
            String val = "0" + Integer.toHexString(data[i]);
            hex += val.substring(val.length() - 2);
        }
        return hex;
    }

    /**
     * toHexString - generate a hex string representation of the given array
     *
     * @param data The array to be converted
     * @return The string representation of the given array
     */
    static String toHexString(byte[] data) {
        return toHexString(data, 0, data.length);
    }

    /**
     * toHexString - generate a byte array representation of the specified
     * string
     *
     * @param hexString The string to convert
     * @return The byte array representation of the given string
     */
    static byte[] toByteArray(String hexString) {
        if ((hexString.length() % 2) == 1) {
            //invalid hex string
            return null;
        }
        try {
            int idx = 0;
            byte result[] = new byte[hexString.length() / 2];
            for (int i = 0; i < hexString.length(); i += 2) {
                String val = hexString.substring(i, i + 2);
                int b = Integer.parseInt(val, 16);
                result[idx++] = (byte) b;
            }
            return result;
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * getRandom Return an array of random bytes
     *
     * @param len The number of bytes to return
     * @return
     */
    static byte[] getRandom(int len) {
        byte result[] = new byte[len];
        srand.nextBytes(result);
        return result;
    }

    /**
     * tests if the provided string contains digits only
     *
     * @param s string to test
     * @return
     */
    static boolean isNumeric(String s) {
        boolean rval = true;
        if (s == null || s.length() == 0) {
            rval = false;
        } else {
            for (int i = 0; i < s.length(); i++) {
                if (!Character.isDigit(s.charAt(i))) {
                    rval = false;
                }
            }
        }
        return rval;
    }

    /**
     * tests if the provided string contains hex characters only
     *
     * @param s string to test
     * @return
     */
    static boolean isHex(String s) {
        boolean rval = true;
        if (s == null || s.length() == 0) {
            rval = false;
        } else {
            final String abcdef = "abcdef";
            for (int i = 0; i < s.length(); i++) {
                char c = Character.toLowerCase(s.charAt(i));
                if (!(Character.isDigit(c) || (abcdef.indexOf(c) > -1))) {
                    System.out.println("case 2" + c);
                    rval = false;
                }
            }
        }
        return rval;
    }

    /**
     * tests if the provided string contains letters and digits only
     *
     * @param s string to test
     * @return
     */
    static boolean noAlphaNumeric(String s) {
        boolean rval = true;
        if (s == null || s.length() == 0) {
            rval = false;
        } else {
            for (int i = 0; i < s.length(); i++) {
                if (!Character.isLetterOrDigit(s.charAt(i))) {
                    rval = false;
                }
            }
        }
        return !rval;
    }

    /**
     * makeLink creates a formated HTML link
     *
     * @param url  the URL (with params if needed)
     * @param text the text displayed to the user
     * @return a wrapped string
     */
    protected static String makeLink(String url, String text) {
        return String.format("<a href=\"%s\">%s</a>", url, text);
    }

    /**
     * makeTableData simply wraps a string with td tags
     *
     * @param s the string to wrap
     * @param a alignment (optional: left, center, right. default: left)
     * @return a wrapped string
     */
    private static String makeTableData(String s, String a) {
        return String.format("<td align='%s'>%s</td>", a, s);
    }

    protected static String makeTableData(String s) {
        return makeTableData(s, "left");
    }

    /**
     * makeTableRow simply wraps a string with tr tags
     *
     * @param s the string to wrap
     * @return a wrapped string
     */
    protected static String makeTableRow(String s) {
        return String.format("\n<tr>%s</tr>", s);
    }

    /**
     * makeFormItem makes a http form item
     *
     * @param name  the name of the form item
     * @param type  the type of the form item (text, button, radio, checkbox, password)
     * @param size  the size to display (only on text/pass)
     * @param maxl  the maxlen (only on text/pass)
     * @param value the value for the item
     * @param check non-zero if checked (only on checkbox / radio)
     * @param reado non-zero if the item is readonly
     * @return a string with the formatted form item
     */
    protected static String makeFormItem(String name, String type, int size, int maxl, String value, int check, int reado) {
        String rval = "";
        int canBchecked = 0;
        int canBreadonly = 0;
        if (type.equalsIgnoreCase("text")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" size=\"%s\" maxlength=\"%s\" value=\"%s\"", name, type, size, maxl, value);
            canBreadonly = 1;
        } else if (type.equalsIgnoreCase("password")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" size=\"%s\" maxlength=\"%s\" value=\"%s\"", name, type, size, maxl, value);
            canBreadonly = 1;
        } else if (type.equalsIgnoreCase("button")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"", name, type, value);
        } else if (type.equalsIgnoreCase("radio")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"", name, type, value);
            canBchecked = 1;
        } else if (type.equalsIgnoreCase("checkbox")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"", name, type, value);
            canBreadonly = 1;
            canBchecked = 1;
        } else if (type.equalsIgnoreCase("submit")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"", name, type, value);
        } else if (type.equalsIgnoreCase("hidden")) {
            rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"", name, type, value);
        }
        if (check != 0 && canBchecked != 0) {
            rval = rval + " checked";
        }
        if (reado != 0 && canBreadonly != 0) {
            rval = rval + " readonly";
        }
        rval = rval + ">";
        return rval;
    }

    /**
     * CodeBreakOutputStream
     * This class wraps a DataOutputStream around a ByteArrayOutputStream for
     * convenience in building data packets.
     */

    public static class CodeBreakOutputStream implements DataOutput {

        private final ByteArrayOutputStream baos;
        private final DataOutputStream dos;

        /**
         * CodeBreakOutputStream
         * This class wraps a DataOutputStream around a ByteArrayOutputStream for
         * convenience in building data packets, for those familiar with these classes
         * the methods should be self explanitory.
         */
        public CodeBreakOutputStream() {
            baos = new ByteArrayOutputStream();
            dos = new DataOutputStream(baos);
        }

        public void write(byte[] b) throws IOException {
            dos.write(b);
        }

        public void write(byte[] b, int off, int len) throws IOException {
            dos.write(b, off, len);
        }

        public void write(int b) throws IOException {
            dos.write(b);
        }

        public void writeBoolean(boolean v) throws IOException {
            dos.writeBoolean(v);
        }

        public void writeByte(int v) throws IOException {
            dos.writeByte(v);
        }

        public void writeBytes(String s) throws IOException {
            dos.writeBytes(s);
        }

        public void writeChar(int v) throws IOException {
            dos.writeChar(v);
        }

        public void writeChars(String s) throws IOException {
            dos.writeChars(s);
        }

        public void writeDouble(double v) throws IOException {
            dos.writeDouble(v);
        }

        public void writeFloat(float v) throws IOException {
            dos.writeFloat(v);
        }

        public void writeInt(int v) throws IOException {
            dos.writeInt(v);
        }

        public void writeLong(long v) throws IOException {
            dos.writeLong(v);
        }

        public void writeShort(int v) throws IOException {
            dos.writeShort(v);
        }

        public void writeTo(OutputStream out) throws IOException {
            dos.flush();
            baos.writeTo(out);
        }

        public void writeUTF(String s) throws IOException {
            dos.writeUTF(s);
        }

        public byte[] toByteArray() {
            try {
                dos.flush();
            } catch (Exception ignored) {
            }
            return baos.toByteArray();
        }

        public int size() {
            try {
                dos.flush();
            } catch (Exception ignored) {
            }
            return baos.size();
        }
    }
}

