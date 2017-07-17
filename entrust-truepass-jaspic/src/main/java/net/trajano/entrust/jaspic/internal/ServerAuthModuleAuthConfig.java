package net.trajano.entrust.jaspic.internal;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import net.trajano.entrust.jaspic.EntrustTruePassJaspicModule;
import net.trajano.entrust.jaspic.EntrustTruePassPrincipalProvider;

/**
 * Provides initialized server modules/contexts.
 */
public class ServerAuthModuleAuthConfig implements
    ServerAuthConfig {

    private static final String JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";

    /**
     * Mandatory message policy.
     */
    protected static final MessagePolicy MANDATORY = new MessagePolicy(new TargetPolicy[0], true);

    /**
     * Non-mandatory message policy.
     */
    protected static final MessagePolicy NON_MANDATORY = new MessagePolicy(new TargetPolicy[0], false);

    /**
     * Application context.
     */
    private final String appContext;

    /**
     * Callback handler.
     */
    private final CallbackHandler handler;

    /**
     * Layer. Usually HttpServlet or SOAPMessage.
     */
    private final String layer;

    private EntrustTruePassPrincipalProvider principalProvider;

    private String websphereUser;

    /**
     * @param layer
     *            layer
     * @param appContext
     *            application context
     * @param handler
     *            handler
     * @param principalProvider
     * @param websphereUser
     *            WebSphere user
     */
    public ServerAuthModuleAuthConfig(final String layer,
        final String appContext,
        final CallbackHandler handler,
        EntrustTruePassPrincipalProvider principalProvider,
        String websphereUser) {
        this.appContext = appContext;
        this.layer = layer;
        this.handler = handler;
        this.principalProvider = principalProvider;
        this.websphereUser = websphereUser;
    }

    public String getAppContext() {

        System.out.println("appContext = " + appContext);
        return appContext;
    }

    /**
     * Checks for the presence of
     * {@value #JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY} in the
     * map.
     *
     * @param messageInfo
     *            contains the message request, response and some system
     *            populated map.
     * @return the string representation of the {@link MessageInfo} if it is
     *         mandatory, <code>null</code> otherwise.
     */
    public String getAuthContextID(final MessageInfo messageInfo) {

        System.out.println("getAuthContextID" + messageInfo);
        final Object isMandatory = messageInfo.getMap().get(JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY);
        if (isMandatory != null && isMandatory instanceof String && Boolean.valueOf((String) isMandatory)) {
            return messageInfo.toString();
        }
        return null;
    }

    protected CallbackHandler getHandler() {

        System.out.println("getHandler=" + handler);

        return handler;
    }

    public String getMessageLayer() {

        return layer;
    }

    public boolean isProtected() {

        return true;
    }

    /**
     * Does nothing as the module does not accept changes at runtime.
     */
    public void refresh() {

        System.out.println("ServerAuth.refresh()");

    }

    @Override
    public ServerAuthContext getAuthContext(final String authContextID,
        final Subject serviceSubject,
        @SuppressWarnings("rawtypes") final Map properties) throws AuthException {

        System.out.println("getAuthContext " + authContextID + serviceSubject + properties);
        final ServerAuthContext context = new EntrustTruePassJaspicModule(principalProvider, websphereUser);

        final ServerAuthModule module = (ServerAuthModule) context;
        if (authContextID == null) {
            module.initialize(NON_MANDATORY, NON_MANDATORY, getHandler(), properties);
        } else {
            module.initialize(MANDATORY, MANDATORY, getHandler(), properties);
        }
        return context;
    }
}
