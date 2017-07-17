package net.trajano.entrust.jaspic;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public abstract class BaseEntrustTruePassServletContextInitializer implements
    ServletContextListener {

    /**
     * Registration ID for the provider. Used for removing the registration when
     * {@link #contextDestroyed(ServletContextEvent)}.
     */
    private String registrationID;

    /**
     * Principal provider.
     */
    private EntrustTruePassPrincipalProvider principalProvider;

    /**
     * Removes the registration for the AuthConfigProvider. {@inheritDoc}
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {

        AuthConfigFactory.getFactory().removeRegistration(registrationID);
    }

    /**
     * The concrete listener would provide this.
     * 
     * @return
     */
    protected abstract EntrustTruePassPrincipalProvider getPrincipalProvider();

    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final ServletContext context = sce.getServletContext();
        //      String virtualServerName = (String) context.getAttribute("EntrustTruePass.VIRTUAL_SERVER_NAME");
        //      String websphereUser = (String) context.getAttribute("EntrustTruePass.WEBSPHERE_USER");
        String virtualServerName = "default_host";
        String websphereUser = "websphere";
        registrationID = AuthConfigFactory.getFactory().registerConfigProvider(
            new EntrustTruePassAuthConfigProvider(principalProvider, websphereUser), "HttpServlet",
            virtualServerName + " " + context.getContextPath(), "JEE Sample");
        System.out.println("registrationID = " + registrationID);
    }
}
