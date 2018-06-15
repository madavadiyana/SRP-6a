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

package com.madavadiyana.springridge.srp.core;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Arul Madavadiyan (arul.madavadiyan@gmail.com)
 *
 */
public class SrpClient extends SrpBase {
    private BigInteger a;   
    private static final int SMALL_A_SIZE = 128;

    public SrpClient(final String userName, final String password) {
        super(userName, password);
    }

    public BigInteger calculateA() {
        final SecureRandom random = new SecureRandom();
        a = new BigInteger(SMALL_A_SIZE, random);
        A = G.modPow(a, N);
        return A;
    }

    /*
     * Calculate the client's premaster secret 
     * S = (B - (k * g^x)) ^ (a + (u * x)) % N
     */
    public BigInteger calculateClientSecret(BigInteger b, String salt) throws Exception {
        B = b;
        BigInteger u = calculateU(A, B);

        // Calculate X from the salt.
        BigInteger x = this.calculateX(salt);
        
        // Calculate bx = g^x % N
        BigInteger bx = G.modPow(x, N);

        // Calculate ((B + N * k) - k * bx) % N
        BigInteger btmp = B.add(N.multiply(K)).subtract(bx.multiply(K)).mod(N);

        // Finish calculation of the premaster secret.
        return btmp.modPow(x.multiply(u).add(a), N);
    }
}
