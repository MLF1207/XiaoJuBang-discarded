package cn.edu.scnu.xiaojubang.net;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.InputMismatchException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static cn.edu.scnu.xiaojubang.net.KeyUtils.DEBUG_RSA_PRIVATE_KEY;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.DEBUG_RSA_PUBLIC_KEY;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.decrypt;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.encrypt;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.fromBase64;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.genAESKey;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.genRSAKey;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.genRSAPrivateKey;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.genRSAPublicKey;
import static cn.edu.scnu.xiaojubang.net.KeyUtils.toBase64;

public class Server {

    private static RSAPrivateKey loadRSAPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        if (System.getenv("debug") != null) {
            return genRSAPrivateKey(DEBUG_RSA_PRIVATE_KEY.getBytes());
        } else {
            String pathname = Server.class.getResource("").getPath() + "xiaojubang.pkcs8_base64";
            FileInputStream fis = new FileInputStream(pathname);
            byte[] b = new byte[fis.available()];
            for (int count = 0; count != b.length; count += fis.read(b, count, b.length - count)) {
            }
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fromBase64(b)));
        }
    }

    private static RSAPublicKey loadRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        if (System.getenv("debug") != null) {
            return genRSAPublicKey(DEBUG_RSA_PUBLIC_KEY.getBytes());
        } else {
            String pathname = Server.class.getResource("").getPath() + "xiaojubang.x509_base64";
            FileInputStream fis = new FileInputStream(pathname);
            byte[] b = new byte[fis.available()];
            for (int count = 0; count != b.length; count += fis.read(b, count, b.length - count)) {
            }
            return genRSAPublicKey(b);
        }
    }

    private static void gen() throws NoSuchAlgorithmException, IOException {
        String pathname = Server.class.getResource("").getPath() + "xiaojubang";
        KeyPair pair = genRSAKey();
        File pri = new File(pathname + ".pkcs8_base64");
        File pub = new File(pathname + ".x509_base64");
        FileWriter priFW = new FileWriter(pri);
        FileWriter pubFW = new FileWriter(pub);
        priFW.write(toBase64(pair.getPrivate().getEncoded()));
        priFW.close();
        pubFW.write(toBase64(pair.getPublic().getEncoded()));
        pubFW.close();
        pri.setWritable(false);
        pri.setExecutable(false);
        pub.setWritable(false);
        pub.setExecutable(false);
        System.out.println("generate successfully.");
    }

    private static void run() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        RSAPrivateKey pri = loadRSAPrivateKey();
        RSAPublicKey pub = loadRSAPublicKey();
        System.out.println(new String(decrypt(pri, encrypt(pub, "hello world.".getBytes()))));
        SecretKey sk = genAESKey();
        System.out.println(new String(decrypt(sk, encrypt(sk, "hello world.".getBytes()))));
    }

    public static void main(String[] args) {
        String show = "" +
                "Select the action you want. )\n" +
                "----------------------------)\n" +
                "   1. generate RSA KeyPair);\n" +
                "   2. run the service);\n" +
                "else. exit);\n";
        System.out.println(show);
        int num = 0;
        try {
            Scanner scanner = new Scanner(System.in);
            num = scanner.nextInt();
        } catch (InputMismatchException e) {
        }

        try {
            if (num == 1) {
                gen();
            } else if (num == 2) {
                run();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
