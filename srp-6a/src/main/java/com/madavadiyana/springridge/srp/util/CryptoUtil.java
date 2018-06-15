/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.madavadiyana.springridge.srp.util;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Arul Madavadiyan  (arul.madavadiyan@gmail.com)
 *
 */
public class CryptoUtil {
    //Algorithm and provider reference can be found in: 
    //http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html

    private static final String AES_DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String BOUNCY_CASTLE_PROVIDER = "BC";
    public static final String DEFAULT_CHARSET = "UTF-8";
    private static final String AES_ALG_NAME = "AES";
    private static final String SHA512_DIGEST_NAME = "SHA-512";
    private static final String SHA256_DIGEST_NAME = "SHA-256";
    private static final String HMAC_ALGO = "HmacSHA512";
    private static final String HMAC_ALGO_SHA256 = "HmacSHA256";
    public static final int DEFAULT_SALT_SIZE = 128;
    public static final String DEFAULT_DIGEST_NAME = SHA512_DIGEST_NAME;
    public static final String DEFAULT_ENCRYPTION_ALGORITHM = AES_ALG_NAME;
    public static final String DEFAULT_HMAC_ALGO = HMAC_ALGO;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    ;
    
    public static byte[] getAESKey(final int size) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALG_NAME, BOUNCY_CASTLE_PROVIDER);
        keyGen.init(size);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static final int getRandomInt(final int max) {
        final SecureRandom secureRandom = new SecureRandom();
        double doubleValue = secureRandom.nextDouble();
        return (int) (doubleValue * max);
    }

    public static final byte[] getRandomBytes(final int size) {
        final SecureRandom secureRandom = new SecureRandom();
        return secureRandom.generateSeed(size);
    }

    public static String encrypt(final String plainText, final byte[] key, final byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES_ALG_NAME);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return encodeBase64(cipher.doFinal(plainText.getBytes(DEFAULT_CHARSET)));
    }

    public static String decrypt(final String cipherText, final byte[] key, final byte[] iv) throws Exception {
        final Cipher cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES_ALG_NAME);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        return new String(cipher.doFinal(decodeBase64(cipherText)), DEFAULT_CHARSET);
    }

    public static final String sha512(final String message, final byte[] salt, final int iterations) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(SHA512_DIGEST_NAME, BOUNCY_CASTLE_PROVIDER);
        digest.reset();
        digest.update(salt);
        byte[] digestValue = digest.digest(message.getBytes(DEFAULT_CHARSET));
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            digestValue = digest.digest(digestValue);
        }
        return encodeBase64(digestValue);
    }

    public static final String sha256(final String message, final byte[] salt, final int iterations) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(SHA256_DIGEST_NAME, BOUNCY_CASTLE_PROVIDER);
        digest.reset();
        if (salt != null && salt.length > 0) {
            digest.update(salt);
        }
        byte[] digestValue = digest.digest(message.getBytes(DEFAULT_CHARSET));
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            digestValue = digest.digest(digestValue);
        }
        return Hex.encodeHexString(digestValue);
    }

    public static final String hexString(final String string, final boolean pad) {
        final String temp;
        if (pad) {
            temp = (string.length() % 2 != 0) ? '0' + string : string;
        } else {
            temp = string;
        }
        String hexString = Hex.encodeHexString(temp.getBytes());
        return hexString;
    }

    public static final String getHmac(final String data, final byte[] key) throws Exception {
        final Mac mac = Mac.getInstance(HMAC_ALGO, BOUNCY_CASTLE_PROVIDER);
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_ALGO);
        mac.init(secretKeySpec);
        final byte[] hmac = mac.doFinal(data.getBytes(DEFAULT_CHARSET));

        return encodeBase64(hmac);
    }

    public static final String getHmacHex(final String data, final byte[] key) throws Exception {
        final Mac mac = Mac.getInstance(HMAC_ALGO_SHA256, BOUNCY_CASTLE_PROVIDER);
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_ALGO);
        mac.init(secretKeySpec);
        final byte[] hmac = mac.doFinal(data.getBytes(DEFAULT_CHARSET));

        return Hex.encodeHexString(hmac);
    }

    public static String encodeBase64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static byte[] decodeBase64(final String str) {
        return Base64.decodeBase64(str);
    }
}
