package org.apache.catalina.core;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TomcatGlobalAuthenticationPasswordUtils {
    private static Log log = LogFactory.getLog(TomcatGlobalAuthenticationPasswordUtils.class);
    private static final String PASSWORD_PATH = System.getProperty("user.home") + "/cooldesktop-work/";
    private static final String PASSWORD_FILE_NAME = "password.conf";
    private static final String DEFAULT_PASSWORD="CE3DEB59B9EE91C3067FDFF1E458B7F0";
    public static void createIfNotExist() {
        try {
            if (!Files.exists(Paths.get(PASSWORD_PATH, PASSWORD_FILE_NAME))) {
                Files.createDirectories(Paths.get(PASSWORD_PATH));
                Files.write(Paths.get(PASSWORD_PATH, PASSWORD_FILE_NAME), DEFAULT_PASSWORD.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            log.info("无法创建密码文件" + e.getMessage());
        }
    }

    public static String getPassword() {
        createIfNotExist();
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(PASSWORD_PATH, PASSWORD_FILE_NAME));
            return new String(bytes);
        } catch (IOException e) {
            log.info("无法获取密码文件" + e.getMessage());
        }
        return "";
    }

}
