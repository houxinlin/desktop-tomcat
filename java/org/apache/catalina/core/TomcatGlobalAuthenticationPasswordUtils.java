package org.apache.catalina.core;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TomcatGlobalAuthenticationPasswordUtils {
    private static Log log = LogFactory.getLog(TomcatGlobalAuthenticationPasswordUtils.class);
    private static final String PASSWORD_PATH = System.getProperty("user.home") + "/desktop-tomcat";
    private static final String PASSWORD_FILE_NAME = "password";

    public static void createIfNotExist() {
        try {
            if (!Files.exists(Paths.get(PASSWORD_PATH, PASSWORD_FILE_NAME))) {
                Files.createDirectories(Paths.get(PASSWORD_PATH));
                Files.write(Paths.get(PASSWORD_PATH, PASSWORD_FILE_NAME), getRandomPassword().getBytes(StandardCharsets.UTF_8));
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

    private static String getRandomPassword() {
        String candidate = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm123456789";
        return RandomStringUtils.random(6, candidate);
    }
}
