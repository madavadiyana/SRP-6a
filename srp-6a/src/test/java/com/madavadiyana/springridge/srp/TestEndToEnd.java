package com.madavadiyana.springridge.srp;

import java.math.BigInteger;
import java.util.Random;
import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

/**
 *
 * @author Arul Madavadiyan (arul.madavadiyan@gmail.com)
 *
 */
public class TestEndToEnd {
    private static final Log LOG = LogFactory.getLog(TestEndToEnd.class);
    private static final int NUMBER_OF_ITERATIONS = 100; // Repeat the test for 100 times with randomly generated username and password at each iteration.
    private static final int USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN = 10;
    private static final int USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX = 40;

    @Test
    public void testSrpPositive() throws Exception {
        for (int i = 0; i < NUMBER_OF_ITERATIONS; i++) {
            final String salt = IdGenerator.getNewId(128, null);
            final int userNameSize = new Random().nextInt(USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX - USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN) + USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN;
            final String userName = IdGenerator.getNewId(userNameSize, null);
            final int passwordSize = new Random().nextInt(USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX - USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN) + USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN;
            final String password = IdGenerator.getNewId(passwordSize, null);
            LOG.info("Username: " + userName + ", password: " + password + ", Salt: " + salt); 
            verify(userName, password, password, salt, true);
        }
    }

    @Test
    public void testSrpNegative() throws Exception {
        for (int i = 0; i < NUMBER_OF_ITERATIONS; i++) {
            final String salt = IdGenerator.getNewId(128, null);
            final int userNameSize = new Random().nextInt(USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX - USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN) + USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN;
            final String userName = IdGenerator.getNewId(userNameSize, null);
            final int passwordSize = new Random().nextInt(USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX - USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN) + USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN;
            final String password = IdGenerator.getNewId(passwordSize, null);
            final int inCorrectPasswordSize = new Random().nextInt(USER_NAME_AND_PASSWORD_SIZE_RANGE_MAX - USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN) + USER_NAME_AND_PASSWORD_SIZE_RANGE_MIN + 1;
            final String incorrectPassword = IdGenerator.getNewId(inCorrectPasswordSize, null);

            verify(userName, password, incorrectPassword, salt, false);
        }
    }

    private void verify(final String userName, String realPassword, final String passwordEnteredByUser, final String salt, boolean testFor) throws Exception {
        //Create username and password as part of Sign-Up/Enrollment Process
        SrpServer createUserNameAndPassword = new SrpServer(userName, realPassword);
        BigInteger v = createUserNameAndPassword.calculateV(salt); //v will get stored in DB

        //Authentication.
        //First Call
        SrpClient client = new SrpClient(userName, passwordEnteredByUser);
        BigInteger A = client.calculateA();

        //(mimic) Client now calls Server with A
        //Server will know V in real life as it is stored in DB.
        SrpServer server = new SrpServer(A, v);
        BigInteger B = server.calculateB();

        //B and salt are received from server.
        //Both client and server generates client secret. 
        //Secrets can be sent to server (optionally) if you do not want to use it further future transactions. Otherwise mutual auth based on signature should be done.
        BigInteger clientSecret = client.calculateClientSecret(B, salt);
        BigInteger serverSecret = server.calculateServerSecret();

        if (testFor) {
            //Verify Signature
            TestCase.assertEquals(realPassword, passwordEnteredByUser);
            TestCase.assertEquals(serverSecret, clientSecret);
            
            //Mutual Auth @Server side - M1 is sent by client to server for verification
            String m1ClientSignature = client.calculateM1(clientSecret);
            String m1ServerSignature = server.calculateM1(serverSecret);
            TestCase.assertEquals(m1ServerSignature, m1ClientSignature);
            
            //Mutual Auth @Client Side - M2 is sent by server to client for verification
            String m2ClientSignature = client.calculateM2(clientSecret, m1ClientSignature);
            String m2ServerSignature = server.calculateM2(serverSecret, m1ClientSignature);
            TestCase.assertEquals(m2ServerSignature, m2ClientSignature);
        } else {
            TestCase.assertNotSame(serverSecret, clientSecret);
            TestCase.assertNotSame(realPassword, passwordEnteredByUser);
        }
    }
}
