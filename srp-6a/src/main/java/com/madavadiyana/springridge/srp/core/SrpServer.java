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
public class SrpServer extends SrpBase {

    private BigInteger b;
    private BigInteger v;

    /**
     * User only when user signs up or sets new password.
     * @param userName - username
     * @param password
     */
    public SrpServer(final String userName, final String password) {
        this.userName = userName;
        this.password = password;
    }

    /**
     * This constuctor is used during authentication.
     * @param A
     * @param v 
     */
    public SrpServer(BigInteger A, BigInteger v) {
        this.A = A;
        this.v = v;
    }

    public BigInteger calculateV(String salt) throws Exception {
        final BigInteger x = this.calculateX(salt);
        return G.modPow(x, N);
    }

    public BigInteger calculateB() {
        final SecureRandom random = new SecureRandom();
        b = new BigInteger(SMALL_B_SIZE, random);
        BigInteger bb = this.G.modPow(b, this.N);
        B = bb.add(v.multiply(this.K)).mod(this.N);
        return B;
    }

    public BigInteger calculateServerSecret() throws Exception {
        BigInteger u = calculateU(A, B);
        return v.modPow(u, this.N).multiply(A)
                .mod(this.N).modPow(b, this.N);
    }
}
