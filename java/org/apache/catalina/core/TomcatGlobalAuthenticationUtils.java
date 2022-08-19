package org.apache.catalina.core;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.jar.JarFile;

public class TomcatGlobalAuthenticationUtils {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    static class ApplicationHome {
        private boolean isUnitTest() {
            try {
                StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
                for (int i = stackTrace.length - 1; i >= 0; --i) {
                    if (stackTrace[i].getClassName().startsWith("org.junit.")) {
                        return true;
                    }
                }
            } catch (Exception var3) {
            }

            return false;
        }

        private File findSource(URL location) throws IOException, URISyntaxException {
            URLConnection connection = location.openConnection();
            return connection instanceof JarURLConnection ? this.getRootJarFile(((JarURLConnection) connection).getJarFile()) : new File(location.toURI());
        }

        private File getRootJarFile(JarFile jarFile) {
            String name = jarFile.getName();
            int separator = name.indexOf("!/");
            if (separator > 0) {
                name = name.substring(0, separator);
            }

            return new File(name);
        }

        public File findHomeDir() {
            File source = findSource(TomcatGlobalAuthenticationUtils.class);
            File homeDir = source != null ? source : null;
            if (homeDir.isFile()) {
                homeDir = homeDir.getParentFile();
            }

            homeDir = homeDir.exists() ? homeDir : new File(".");
            return homeDir.getAbsoluteFile();
        }

        private File findSource(Class<?> sourceClass) {
            try {
                ProtectionDomain domain = sourceClass != null ? sourceClass.getProtectionDomain() : null;
                CodeSource codeSource = domain != null ? domain.getCodeSource() : null;
                URL location = codeSource != null ? codeSource.getLocation() : null;
                File source = location != null ? this.findSource(location) : null;
                if (source != null && source.exists() && !this.isUnitTest()) {
                    return source.getAbsoluteFile();
                }
            } catch (Exception var6) {
            }

            return null;
        }
    }

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
