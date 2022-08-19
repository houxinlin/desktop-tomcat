package org.apache.catalina.core;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.apache.tomcat.util.http.fileupload.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class TomcatGlobalAuthenticationValve extends ValveBase {
    public static final String SESSION_ATTRIBUTE_KEY = "authentication";
    private static final String SESSION_ATTRIBUTE_VALUE = "true";
    private static final String TOMCAT_LOGIN_PATH = "tomcat/tomcat-index.html";
    private static final String TOMCAT_API_PREFIX = "/tomcat/api";
    private static final String OPEN_FILE = "work/config/o_urls/config";
    private static final Log log = LogFactory.getLog(TomcatGlobalAuthenticationValve.class);

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
        response.setCharacterEncoding("UTF-8");
        //如果是开放url
        if (isOpenUrl(request.getRequestURI())) {
            getNext().invoke(request, response);
            return;
        }
        //如果已经认证了
        if (SESSION_ATTRIBUTE_VALUE.equals(request.getSession().getAttribute(SESSION_ATTRIBUTE_KEY))) {
            //如果是重置密码请求，则将cookie删除
            if (request.getRequestURI().startsWith("/desktop/api/system/resetLoginPasswd")) {
                request.clearCookies();
                request.getSession().removeAttribute(SESSION_ATTRIBUTE_KEY);
            }
            if (TomcatGlobalAuthenticationHttpServlet.TOMCAT_URL_LOGOUT.equals(request.getRequestURI())) {
                request.getSession().removeAttribute(TomcatGlobalAuthenticationValve.SESSION_ATTRIBUTE_KEY);
                response.sendRedirect("/");
                return;
            }
            getNext().invoke(request, response);
            return;
        }
        //处理接口
        if (request.getRequestURI().startsWith(TOMCAT_API_PREFIX)) {
            doHandlerTomcatApi(request, response);
            return;
        }
        //没认证
        setHttpResponseDefaultConfig(response);
        InputStream indexPageResource = getIndexPageResource();
        //没有找到index.html
        if (indexPageResource == null) {
            replyDefaultPage(response);
            return;
        }
        //返回登录页面
        replyTomcatLoginPage(indexPageResource, response);
    }

    /**
     * 是否开放URL
     *
     * @param requestUrl
     * @return
     */
    private static boolean isOpenUrl(String requestUrl) {
        URI requestURI = URI.create(requestUrl);

        TomcatGlobalAuthenticationUtils.ApplicationHome applicationHome = new TomcatGlobalAuthenticationUtils.ApplicationHome();
        File source = applicationHome.findHomeDir();
        File openFile = new File(source, OPEN_FILE);
        if (!openFile.exists()) {
            return false;
        }
        try {
            List<String> strings = Files.readAllLines(Paths.get(openFile.getAbsolutePath()));
            for (String item : strings) {
                if (requestURI.getPath().equals(item)) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;

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
        httpServletResponse.addHeader("Cache-Control", "no-cache");

    }

    private void replyTomcatLoginPage(InputStream inputStream, Response response) {
        try {
            HttpServletResponse httpServletResponse = response.getResponse();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            IOUtils.copy(inputStream, outputStream);
            String htmlBody = new String(outputStream.toByteArray());
            String newHtml = htmlBody.replace("${rsapublic}", TomcatGlobalAuthenticationUtils.getPublicKey());
            httpServletResponse.getOutputStream().write(newHtml.getBytes(StandardCharsets.UTF_8));
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
