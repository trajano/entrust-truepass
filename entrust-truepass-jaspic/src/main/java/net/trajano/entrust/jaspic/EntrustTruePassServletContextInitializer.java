package net.trajano.entrust.jaspic;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class EntrustTruePassServletContextInitializer implements
    ServletContextListener {

    /**
     * Registers the authentication modules. {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final Map<String, String> options = new ConcurrentHashMap<String, String>();
        AuthConfigFactory.getFactory()
            .registerConfigProvider(EntrustTruePassAuthModuleConfigProvider.class.getName(), options, "HttpServlet", null, null);
    }

    /**
     * Does nothing. {@inheritDoc}
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {

    }
}
