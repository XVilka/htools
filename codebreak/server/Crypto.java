/*
    Code Break HmacMD5
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Crypto
 * This class is responsible for computing an Crypto value
 * for use in the challenge and response authentication portion
 * of a collabreate server connection, see RFC 2104
 */

public class Crypto {
    /**
     * HMAC_MD5 calculates an Hmac MD5 value
     *
     * @param msg a byte array to hash
     * @param key a byte array to use as the HMAC_MD5 key
     * @return the hmacMD5
     */
    static byte[] HMAC_MD5(byte[] msg, byte[] key) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception ignored) {
        }
        if (key.length > 64) {
            md5.reset();
            key = md5.digest(key);
        }
        byte ipad[] = new byte[64];
        System.arraycopy(key, 0, ipad, 0, key.length);
        byte opad[] = ipad.clone();

        /* XOR key with ipad and opad values */
        for (int i = 0; i < ipad.length; i++) {
            ipad[i] ^= (byte) 0x36;
            opad[i] ^= (byte) 0x5c;
        }

        // perform inner MD5
        md5.reset();
        md5.update(ipad);
        byte digest[] = md5.digest(msg);

        // perform outer MD5
        md5.reset();
        md5.update(opad);
        return md5.digest(digest);
    }

    /**
     * HMAC_SHA1 calculates an Hmac SHA1 value
     *
     * @param msg a byte array to hash
     * @param key a byte array to use as the HMAC_SHA1 key
     * @return the hmacSHA1
     */
    protected static byte[] HMAC_SHA1(byte[] msg, byte[] key) {
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (Exception ignored) {
        }
        if (key.length > 64) {
            sha1.reset();
            key = sha1.digest(key);
        }
        byte ipad[] = new byte[64];
        System.arraycopy(key, 0, ipad, 0, key.length);
        byte opad[] = ipad.clone();

        /* XOR key with ipad and opad values */
        for (int i = 0; i < ipad.length; i++) {
            ipad[i] ^= (byte) 0x36;
            opad[i] ^= (byte) 0x5c;
        }

        // perform inner MD5
        sha1.reset();
        sha1.update(ipad);
        byte digest[] = sha1.digest(msg);

        // perform outer MD5
        sha1.reset();
        sha1.update(opad);
        return sha1.digest(digest);
    }

    /**
     * HASH_MD5 - calculate the md5sum of a string
     *
     * @param tohash The string to hash
     * @return The md5sum of the input string
     */
    public static String HASH_MD5(String tohash) {
        byte[] defaultBytes = tohash.getBytes();
        String hashString = "";
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.reset();
            md5.update(defaultBytes);
            byte hash[] = md5.digest();
            hashString = Utils.toHexString(hash);
        } catch (NoSuchAlgorithmException ignored) {
        }
        return hashString;
    }

    /**
     * HASH_SHA1 - calculate the sha1sum of a string
     *
     * @param tohash The string to hash
     * @return The sha1sum of the input string
     */
    protected static String HASH_SHA1(String tohash) {
        byte[] defaultBytes = tohash.getBytes();
        String hashString = "";
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            sha1.reset();
            sha1.update(defaultBytes);
            byte hash[] = sha1.digest();
            hashString = Utils.toHexString(hash);
        } catch (NoSuchAlgorithmException ignored) {
        }
        return hashString;
    }
}
