package org.apache.catalina.core;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.security.ConcurrentMessageDigest;
import org.apache.tomcat.util.security.MD5Encoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public class TomcatGlobalAuthenticationHttpServlet extends HttpServlet {
    public static final String TOMCAT_API_LOGIN = "/tomcat/api/login";
    public static final String TOMCAT_URL_LOGOUT = "/tomcat/api/logout";
    private static final String IP_LIMIT_TIP = "{\"status\":false,\"msg\":\"此IP已被限制，10分钟后尝试\"}";
    private static final Log log = LogFactory.getLog(TomcatGlobalAuthenticationHttpServlet.class);
    private static final StringManager sm = StringManager.getManager(TomcatGlobalAuthenticationHttpServlet.class);
    private static final int MAX_LOGIN = 5;
    private final Map<String, Integer> ipLimit = new ConcurrentHashMap<>();
    private DelayQueue<IPLimitTask> taskDelayQueue = new DelayQueue<>();

    private static Function<Map<String, Object>, Object> loginCallback;

    public TomcatGlobalAuthenticationHttpServlet() {
        new Thread(() -> {
            while (true) {
                try {
                    IPLimitTask take = taskDelayQueue.take();
                    ipLimit.remove(take.remoteAddr);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static void setCallbackFunction(Function function) {
        log.info("setCallbackFunction ok");
        loginCallback = function;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (TOMCAT_API_LOGIN.equals(req.getRequestURI())) {
            //登录次数上限
            if (MAX_LOGIN == ipLimit.getOrDefault(req.getRemoteAddr(), 0)) {
                if (loginCallback != null) loginCallback.apply(new IpLimitMessage(req.getRemoteAddr()));
                taskDelayQueue.add(new IPLimitTask(req.getRemoteAddr()));
                resp.getWriter().append(IP_LIMIT_TIP);
                return;
            }
            //获取密码
            try {
                String sourcePassword = TomcatGlobalAuthenticationUtils.decrypt(req.getParameter("password").replaceAll(" ", "+"));
                sourcePassword += "cooldesktop@passwd!.";
                String md5pass = MD5Encoder.encode(ConcurrentMessageDigest.digestMD5(sourcePassword.getBytes(StandardCharsets.UTF_8))).toUpperCase();
                if (TomcatGlobalAuthenticationPasswordUtils.getPassword().equals(md5pass)) {
                    log.info(sm.getString("global.authentication.success"));
                    req.getSession().setMaxInactiveInterval((int) TimeUnit.HOURS.toSeconds(1));
                    req.getSession().setAttribute(TomcatGlobalAuthenticationValve.SESSION_ATTRIBUTE_KEY, "true");
                    ipLimit.remove(req.getRemoteAddr());
                    resp.getWriter().append("{\"status\":true}");
                    if (loginCallback != null) loginCallback.apply(new LoginSuccessMessage(req.getRemoteAddr()));
                    return;
                }
            } catch (Exception e) {
                log.info(e.getMessage());
            }
            ipLimit.put(req.getRemoteAddr(), ipLimit.getOrDefault(req.getRemoteAddr(), 0) + 1);
            resp.getWriter().append("{\"status\":false}");
        }
    }


    abstract static class LoginMessage extends HashMap<String, Object> {
        public LoginMessage(String msg, String data, String level) {
            this.put("msg",msg);
            this.put("data",data);
            this.put("level",level);
        }
    }

    static class IpLimitMessage extends LoginMessage {

        public IpLimitMessage(String data) {
            super("登陆次数过多，限制登陆", data, "info");
        }

    }

    static class LoginSuccessMessage extends LoginMessage {
        public LoginSuccessMessage(String data) {
            super("登陆成功", data, "info");
        }
    }

    static class IPLimitTask implements Delayed {
        private String remoteAddr;
        private long expire;

        public IPLimitTask(String remoteAddr) {
            this.remoteAddr = remoteAddr;
            //过期时间在30分钟后
            this.expire = System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.MINUTES);
        }

        @Override
        public long getDelay(TimeUnit unit) {
            return expire - System.currentTimeMillis();
        }

        @Override
        public int compareTo(Delayed o) {
            return (int) (this.expire - ((IPLimitTask) o).expire);
        }
    }
}
