package org.apache.catalina.core;

import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TomcatGlobalAuthenticationHttpServlet extends HttpServlet {
    private static final String TOMCAT_API_LOGIN = "/tomcat/api/login";
    private Log log = LogFactory.getLog(TomcatGlobalAuthenticationHttpServlet.class);
    protected static final StringManager sm = StringManager.getManager(TomcatGlobalAuthenticationHttpServlet.class);
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (TOMCAT_API_LOGIN.equals(req.getRequestURI())) {
            String password = req.getParameter("password");
            if (TomcatGlobalAuthenticationPasswordUtils.getPassword().equals(password)) {
                log.info(sm.getString("global.authentication.success"));
                req.getSession().setAttribute(TomcatGlobalAuthenticationValve.SESSION_ATTRIBUTE_KEY, "true");
                resp.getWriter().append("{\"status\":true}");
                return;
            }
            resp.getWriter().append("{\"status\":false}");
        }
    }
}
