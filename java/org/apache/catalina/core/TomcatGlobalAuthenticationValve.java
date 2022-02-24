package org.apache.catalina.core;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.apache.tomcat.util.http.fileupload.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TomcatGlobalAuthenticationValve extends ValveBase {
    public static final String SESSION_ATTRIBUTE_KEY = "authenticationed";
    private static final String SESSION_ATTRIBUTE_VALUE = "true";
    private static final String TOMCAT_LOGIN_PATH = "tomcat/tomcat-index.html";
    private static final String TOMCAT_API_PREFIX = "/tomcat/api";
    private Log log = LogFactory.getLog(TomcatGlobalAuthenticationValve.class);

    private TomcatGlobalAuthenticationHttpServlet tomcatGlobalAuthenticationHttpServlet;

    public TomcatGlobalAuthenticationValve() {
        log.info(sm.getString("global.authentication.start"));
        tomcatGlobalAuthenticationHttpServlet = new TomcatGlobalAuthenticationHttpServlet();
        initTomcatAuthenticationPassword();
    }

    private void initTomcatAuthenticationPassword() {
        TomcatGlobalAuthenticationPasswordUtils.createIfNotExist();
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (SESSION_ATTRIBUTE_VALUE.equals(request.getSession().getAttribute(SESSION_ATTRIBUTE_KEY))) {
            getNext().invoke(request, response);
            return;
        }
        setHttpResponseDefaultConfig(response);
        log.info(sm.getString("global.authentication.noauth"));
        if (request.getRequestURI().startsWith(TOMCAT_API_PREFIX)) {
            doHandlerTomcatApi(request, response);
            return;
        }

        InputStream indexPageResource = getIndexPageResource();
        if (indexPageResource == null) {
            replyDefaultPage(response);
            return;
        }
        replyTomcatLoginPage(indexPageResource, response);
    }

    private void doHandlerTomcatApi(Request request, Response response) {
        try {
            tomcatGlobalAuthenticationHttpServlet.doPost(request, response);
        } catch (ServletException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void setHttpResponseDefaultConfig(Response response) {
        HttpServletResponse httpServletResponse = response.getResponse();
        httpServletResponse.setContentType("text/html; charset=utf-8");

    }

    private void replyTomcatLoginPage(InputStream inputStream, Response response) {
        try {
            HttpServletResponse httpServletResponse = response.getResponse();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            IOUtils.copy(inputStream, outputStream);
            httpServletResponse.getOutputStream().write(outputStream.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void replyDefaultPage(Response response) {
        try {
            HttpServletResponse httpServletResponse = response.getResponse();
            StringBuilder defaultPage = new StringBuilder();
            defaultPage.append("<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <title>error</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <div>error auth</div>\n" +
                "</body>\n" +
                "</html>");
            httpServletResponse.getWriter().append(defaultPage.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private InputStream getIndexPageResource() {
        URL resource = TomcatGlobalAuthenticationValve.class.getClassLoader().getResource(TOMCAT_LOGIN_PATH);
        try {
            if (resource != null) {
                return resource.openStream();
            }
        } catch (IOException e) {
            log.info(e.getMessage());
        }
        log.info("login page not exist " + ClassLoader.getSystemResource("") + TOMCAT_LOGIN_PATH);
        return null;
    }
}
