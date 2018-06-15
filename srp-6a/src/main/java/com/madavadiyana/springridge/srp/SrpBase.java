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

package com.madavadiyana.springridge.srp;

import com.madavadiyana.springridge.srp.util.CryptoUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.math.BigInteger;
import org.apache.commons.codec.binary.Hex;


/**
 * SRP 6a Algorithm for Mutual Authentication. 
 * 
 * Here are the steps as described in http://srp.stanford.edu/design.html and https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
 *
 * 1) The client generates a and A from Password. Client sends username and A to server. 
 * 2) Server generates b and B. B is generated from b and v (verifier from DB)
 * 3) Client and the server both generate U from A and B. 
 * 4) Client generates client secret and sends signature to server (M1). 
 * 5) Server generates server Secret and generates its own M1. Then compare with client's M1
 * 6) Server generates M2 and send to Client
 * 7) Client generates its own M2 and compares. Now mutual auth is established (without sending password nor secret).
 *
 * @author Arul Madavadiyan (arul.madavadiyan@gmail.com)
 *
 */
public abstract class SrpBase {

    protected String userName;
    protected String password;
    protected int keySizeInBits;
    protected BigInteger A;
    protected BigInteger B;
    private static final Log LOG = LogFactory.getLog(SrpBase.class);

    protected static final String INIT_N = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
            + "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
            + "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
            + "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
            + "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
            + "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
            + "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
            + "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
            + "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
            + "9E4AFF73";

    protected static final String INIT_G = "2";

    protected static final int HEX_RADIX = 16;
    protected static final int SMALL_B_SIZE = 64;
    protected static final BigInteger N = new BigInteger(INIT_N, HEX_RADIX);
    protected static final BigInteger G = new BigInteger(INIT_G, HEX_RADIX);
    protected static final BigInteger K = calculateK();

    public SrpBase(final String userName, final String password, final int keySizeInBits) {
        this.userName = userName;
        this.password = password;
        this.keySizeInBits = keySizeInBits;
    }

    public SrpBase() {
    }

    protected static BigInteger calculateK() {
        try {
            String[] array = {N.toString(HEX_RADIX), G.toString(HEX_RADIX)};
            BigInteger returnValue = paddedHash(array);

            return returnValue;
        } catch (Exception e) {
            LOG.error("Unable to compute k: {0}", e);
        }
        return null;
    }

    public static BigInteger paddedHash(String[] array) throws Exception {
        int nlen = 2 * ((N.toString(16).length() * 4 + 7) >> 3);
        String toHash = "";
        for (String array1 : array) {
            toHash += nZeros(nlen - array1.length()) + array1;
        }
        BigInteger hash = new BigInteger(CryptoUtil.sha256(toHash, null, 0), 16);
        return hash.mod(N);

    }

    public static String nZeros(int n) {
        final StringBuilder builder = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            builder.append("0");
        }
        return builder.toString();
    }

    public BigInteger calculateU(BigInteger A, BigInteger B) throws Exception {
        String[] array = {A.toString(HEX_RADIX), B.toString(HEX_RADIX)};
        return paddedHash(array);
    }

    public String calculateSignature(final String someValue, String clientSignature, String serverSecret) throws Exception {
        final String spad = (serverSecret.length() % 2 != 0) ? "0" : "";
        serverSecret = spad + serverSecret;
        String[] array = {someValue, clientSignature, serverSecret};
        BigInteger hash = paddedHash(array);
        return CryptoUtil.getHmacHex(hash.toString(HEX_RADIX), Hex.decodeHex(serverSecret.toCharArray()));
    }

    /**
     * Salt.
     *
     * @param salt
     * @return
     * @throws java.lang.Exception
     */
    public BigInteger calculateX(final String salt) throws Exception {
        // Hash the concatenated username and password.
        final String userNamePassword = this.userName + ":" + this.password;
        final String usernamePasswordHash = CryptoUtil.sha256(userNamePassword, null, 0);
        final String spad = (salt.length() % 2 != 0) ? "0" : "";

        // Calculate the hash of salt + hash(username:password).
        String X = CryptoUtil.sha256(spad + salt + usernamePasswordHash, null, 0);
        return new BigInteger(X, HEX_RADIX);
    }
    
    public String calculateM1(BigInteger secret) throws Exception {
        return calculateSignature(A.toString(HEX_RADIX), B.toString(HEX_RADIX), secret.toString(HEX_RADIX)); 
    }

    public String calculateM2(BigInteger secret, final String clientSignature) throws Exception {
        return calculateSignature(A.toString(HEX_RADIX), clientSignature, secret.toString(HEX_RADIX));
    }    
}
