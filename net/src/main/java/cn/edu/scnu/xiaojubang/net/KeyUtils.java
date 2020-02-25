package cn.edu.scnu.xiaojubang.net;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtils {
    public static final String DEBUG_RSA_PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCLsfsw6qcMKgAzCAilOA7Rq3ungJPK1j9KRqTkFiwTXs7IfLm+piW8SscDvXS851bnJ/zLI+WWBPIENrIZQ23aFIyUWLRpXzFAgT8Zjg040jJ2JBn0ouCA9Kg2eepzJJyMu0gxq7pOJweEztMR1H2ArLNEqj7Knqjq04P3rh7TSUmEyCWvKsO/CnlAMXC23gJi1MbXb1YmtQnp/7ubpJOfT/FDwyGS17hIZx8Eb3XEVWnywVN9uIjPdCSnigQedkPxtQsWdAEI9dRiQZ2h+jS/QagH9HbdpjCx9lRq7oLpqwzwBntUxONL4562zcOqwLMQo/B+jmrm6jP/UFNZZFy1AgMBAAECggEAa/M5vW9Xb1r1lHnc1HAhY300rRf7HX+6oNc+jNNldAKLoPphPyZ9eqf+arF5CJFs4mxQOVqgC/H+Y6swrb0hoqjGicySfesF0GcQL9tJ9GLag9kaBaXn/z8QziggOKJOJ6KCA4BFFCes88Av81NVOJ48Wg+FPmak+fJBxKBVScfv7TlVITN+mkoYblR+nKYSkgDo8txCbX7cirw/jTZcksO68JSy1SHX1H9kkJ8j1UeFmjoniRQ0KKCMkucArASAkxvU7/RL3IgGC/Ai07MhxLDkRRmNW0YN9gIahSX92sVyyvX58ilcdH5impMX9QDsjyPfonOQCXN+qpgDpW7a8QKBgQDFpdE2PilXhU8GfxqcVqVn4pJlky2svX9+VH0jVyUTkd3sIrllOA2Qw5I+onXqzHq0Z7/wF/L7gNUwv8BtX4Ez1L8ghl3xqu8UlElGkIgJs2MO9VPTaylJvl4xCDbRy3m/X3nw77WCo0Ij3dqcl0e84R4nENhPHM8gawv/aPmz4wKBgQC08B/okv3THSiPPdGshG5PhsXK0F88ijig6FiBnUCWjRw4Q0WHKvy3+dNvfyxfX2bq1TuSQAsUsXNacQ9t7XTT0gEtpwd2Yb9SF+bqxeAijhcgg3vjGCEuED6+rPtAIIqlNuQ6ciVISOWf2CxCmCtKVtPHqF9Vc1iQSG4R6jeAhwKBgQCGDZtCcRLVO6OHwnmoA9SYC0JEBnj6KmToqCFf8OFCzrJ4UGzyS/xXbW4pcUMNB7dJ2PyDuZqiHpV6RPQcuqQFJYykYL4jBU625IR2idzax4KuSJKcWJheXfHAy9Nyo9FljTpFwi+X9WcMsJJvluOfJgivcmtj7SRG1pQCnY6PBQKBgQCmIEJru2opR4BR5CR7DSxrAAbia+bFIvNTaYC5oLQIho7+aWWQ8TsPf+VNXapT9rf7rMQBR6Pk3/hVdbEA8SBuy0YhsFX9r0mGCkQOEpfzohpB0/cPTrxIGspBL3mQK1Cg2IE72Em60JNj64rXqfc1TfssOb8uKbWK47WL5UwISQKBgGQEYuBesojL0YiBYGTUjw7nWaxh3N74yZO7+gAWsAgaUx1RF35MwChf8C9CTEgPpzNNppdAgMjSHbFP7gZbIt4A4UA1g6D0v+OxeVisZMuaSg2ltwkCi74AtPeb2lNgqTPBsD2e6hoFLrXsu3WMZBzw68Boytnsw1fKI5FSriaK";
    public static final String DEBUG_RSA_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi7H7MOqnDCoAMwgIpTgO0at7p4CTytY/Skak5BYsE17OyHy5vqYlvErHA710vOdW5yf8yyPllgTyBDayGUNt2hSMlFi0aV8xQIE/GY4NONIydiQZ9KLggPSoNnnqcyScjLtIMau6TicHhM7TEdR9gKyzRKo+yp6o6tOD964e00lJhMglryrDvwp5QDFwtt4CYtTG129WJrUJ6f+7m6STn0/xQ8Mhkte4SGcfBG91xFVp8sFTfbiIz3Qkp4oEHnZD8bULFnQBCPXUYkGdofo0v0GoB/R23aYwsfZUau6C6asM8AZ7VMTjS+Oets3DqsCzEKPwfo5q5uoz/1BTWWRctQIDAQAB";

    public static KeyPair genRSAKey() throws NoSuchAlgorithmException {
        return genRSAKey(2048);
    }

    public static KeyPair genRSAKey(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    public static SecretKey genAESKey() throws NoSuchAlgorithmException {
        return genAESKey(256);
    }

    public static SecretKey genAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(keySize);
        return kg.generateKey();
    }

    public static String toBase64(byte[] keyEncoded) {
        return new String(Base64.getEncoder().encode(keyEncoded));
    }

    public static byte[] fromBase64(byte[] base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static RSAPrivateKey genRSAPrivateKey(byte[] base64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fromBase64(base64)));
    }

    public static RSAPublicKey genRSAPublicKey(byte[] base64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(fromBase64(base64)));
    }

    public static byte[] encrypt(Key key, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(Key key, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static SecretKeySpec genAESKey(byte[] keyEncoded) {
        return new SecretKeySpec(keyEncoded, "AES");
    }

    private KeyUtils() {
    }
}
