package net.trajano.entrust.jaspic;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.module.ClientAuthModule;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletContextEvent;

public class EntrustTruePassServletContextInitializer implements
    ServletContextListener {

    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        Map<String, String> options = new HashMap<String, String>();
        AuthConfigFactory.getFactory()
            .registerConfigProvider(EntrustTruePassAuthModuleConfigProvider.class.getName(), options, "HttpServlet", null, null);
    }
}
