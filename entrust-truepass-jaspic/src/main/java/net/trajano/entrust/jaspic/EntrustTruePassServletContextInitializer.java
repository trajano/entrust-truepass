package net.trajano.entrust.jaspic;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class EntrustTruePassServletContextInitializer implements
    ServletContextListener {

    /**
     * Registers the authentication modules. {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        try {
            final Map<String, String> options = new ConcurrentHashMap<String, String>();
            options.put("com.ibm.websphere.jaspi.configuration",
                (new File((File) sce.getServletContext().getAttribute(ServletContext.TEMPDIR),
                    "jaspi-registrations")).getCanonicalPath());
            AuthConfigFactory.getFactory().registerConfigProvider(
                EntrustTruePassAuthModuleConfigProvider.class.getName(), options, "HttpServlet", null, null);
        } catch (IOException e) {
            throw new IllegalStateException("IOException during initialization", e);
        }
    }

    /**
     * Does nothing. {@inheritDoc}
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {

    }
}
