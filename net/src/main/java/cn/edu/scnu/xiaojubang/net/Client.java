package cn.edu.scnu.xiaojubang.net;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static cn.edu.scnu.xiaojubang.net.KeyUtils.fromBase64;

public class Client {
    private static final String DEBUG_PUBLICKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi7H7MOqnDCoAMwgIpTgO0at7p4CTytY/Skak5BYsE17OyHy5vqYlvErHA710vOdW5yf8yyPllgTyBDayGUNt2hSMlFi0aV8xQIE/GY4NONIydiQZ9KLggPSoNnnqcyScjLtIMau6TicHhM7TEdR9gKyzRKo+yp6o6tOD964e00lJhMglryrDvwp5QDFwtt4CYtTG129WJrUJ6f+7m6STn0/xQ8Mhkte4SGcfBG91xFVp8sFTfbiIz3Qkp4oEHnZD8bULFnQBCPXUYkGdofo0v0GoB/R23aYwsfZUau6C6asM8AZ7VMTjS+Oets3DqsCzEKPwfo5q5uoz/1BTWWRctQIDAQAB";

    private static void getRSAPublicKey(){

    }

    private static RSAPublicKey loadRSAPublicKey(InputStream is) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] b = new byte[is.available()];
        for (int count = 0; count != b.length; count += is.read(b, count, b.length - count) ) {
        }
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fromBase64(b)));
    }
}
