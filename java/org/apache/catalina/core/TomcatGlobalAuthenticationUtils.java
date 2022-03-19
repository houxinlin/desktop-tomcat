package org.apache.catalina.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class TomcatGlobalAuthenticationUtils {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    static {
        generator();
    }



    private static void generator() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String decrypt(String text) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(text)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String encrypt(String text) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String getPrivateKey() {
        return new String(Base64.getEncoder().encode(privateKey.getEncoded()));
    }

    public static String getPublicKey() {
        return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
    }
}
