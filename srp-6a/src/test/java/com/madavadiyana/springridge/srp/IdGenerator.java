package com.madavadiyana.springridge.srp;

import java.security.SecureRandom;
import java.util.Date;
import org.apache.commons.codec.binary.Base64;

/**
 *
 *
 * @author Arul Madavadiyan (arul.madavadiyan@gmail.com)
 *
 */
public class IdGenerator {

    private static final int SEED_SIZE = 1024;

    public static String getNewId(final int size, final String randomString) {
        final String randomSeed = new String(SecureRandom.getSeed(SEED_SIZE)) + new Date().getTime() + "," + randomString;
        String newId = "";
        while (newId.length() < size) {
            final byte[] randomBytes = new byte[size * 2 - newId.length()];
            new SecureRandom(randomSeed.getBytes()).nextBytes(randomBytes);
            newId = newId + Base64.encodeBase64URLSafeString(randomBytes);
        }
        return newId.substring(0, size); 
    }    
}
