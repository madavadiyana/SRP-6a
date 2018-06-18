 SRP 6a Algorithm for Mutual Authentication. 
  
What is SRP: http://srp.stanford.edu/whatisit.html

Here are the steps as described in http://srp.stanford.edu/design.html and https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
 
 1) The client generates a and A from Password. Client sends username and A to server. 
 2) Server generates b and B. B is generated from b and v (verifier from DB)
 3) Client and the server both generate U from A and B. 
 4) Client generates client secret and sends signature to server (M1). 
 5) Server generates server Secret and generates its own M1. Then compare with client's M1
 6) Server generates M2 and send to Client
 7) Client generates its own M2 and compares. Now mutual auth is established (without sending password nor secret).

SRP Login Page: 
    http://34.211.45.2/webcontent/loginSRP.html
    UserName: madavadiyana, Password: TEv7puHvIx1234
    (you can watch for netwok traffic from Chrome's Developer Tools)

Regular Login Page: http://34.211.45.2/webcontent/login.html (same credential as above)

TODO: Code Documentation, Unit Tests but there are 2 end to end integration tests.

Following is example code that establishes Mutual Authentication.

        final String userName = "madavadiyana";
        final String password = "hardPassword$$8902";
        final String salt = "zNqf5f22s_ztf6JPZCWRF2T2CQuSvTXbn9dq-b4WxYNW5oLsqblo7fWN0kj1UCYu7DpaS9Rb506FipdfQgCdcwzChOZlYqVlOun3ZoKdO4WXNcXF6Ysq6Z05HtiYDpmB";

        //Create username and password as part of Sign-Up/Enrollment Process. One time process until you reset the password.
        SrpServer createUserNameAndPassword = new SrpServer(userName, password);
        BigInteger v = createUserNameAndPassword.calculateV(salt); //v will get stored in DB along with Salt.

        //Mutual Authentication Requires two steps.
        //First Step
        SrpClient client = new SrpClient(userName, password); //Change the password here to test the negative test case.
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

        //Second Step
        //Mutual Auth @Server side - M1 is sent by client to server for verification
        String m1ClientSignature = client.calculateM1(clientSecret);
        String m1ServerSignature = server.calculateM1(serverSecret);
        if(!m1ClientSignature.equals(m1ServerSignature)) {
            System.out.println("Server is unable to verify Client's Signature. Fail..");
        }

        //Mutual Auth @Client Side - M2 is sent by server to client for verification
        String m2ClientSignature = client.calculateM2(clientSecret, m1ClientSignature);
        String m2ServerSignature = server.calculateM2(serverSecret, m1ClientSignature);
        
        if(!m2ClientSignature.equals(m2ServerSignature)) {
            System.out.println("Client is unable to verify Server's Signature. Fail");
        } else {
            System.out.println("*** Password is authenticated. Your mutual Auth is now Established ****");
        }