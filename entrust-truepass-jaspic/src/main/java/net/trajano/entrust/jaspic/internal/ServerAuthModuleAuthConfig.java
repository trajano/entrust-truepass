package net.trajano.entrust.jaspic.internal;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;

import net.trajano.entrust.jaspic.EntrustTruePassAuthModuleConfigProvider;
import net.trajano.entrust.jaspic.EntrustTruePassJaspicModule;

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

    /**
     * Setup options.
     */
    private final Map<String, String> options;

    /**
     * @param options
     *            options
     * @param layer
     *            layer
     * @param appContext
     *            application context
     * @param handler
     *            handler
     */
    public ServerAuthModuleAuthConfig(final Map<String, String> options,
        final String layer,
        final String appContext,
        final CallbackHandler handler) {
        this.appContext = appContext;
        this.layer = layer;
        this.options = options;
        this.handler = handler;
    }

    /**
     * Augments the properties with additional properties.
     *
     * @param properties
     *            properties to augment with.
     * @return augmented properties
     */
    @SuppressWarnings("unchecked")
    protected Map<?, ?> augmentProperties(@SuppressWarnings("rawtypes") final Map properties) {

        if (properties == null) {
            return options;
        }
        final Map<String, String> augmentedOptions = new ConcurrentHashMap<String, String>(options);
        augmentedOptions.putAll(properties);
        return augmentedOptions;

    }

    public String getAppContext() {

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

        final Object isMandatory = messageInfo.getMap()
            .get(JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY);
        if (isMandatory != null && isMandatory instanceof String && Boolean.valueOf((String) isMandatory)) {
            return messageInfo.toString();
        }
        return null;
    }

    protected CallbackHandler getHandler() {

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

    }

    @Override
    public ServerAuthContext getAuthContext(final String authContextID,
        final Subject serviceSubject,
        @SuppressWarnings("rawtypes") final Map properties) throws AuthException {

        final Map<?, ?> augmentedOptions = augmentProperties(properties);
        final ServerAuthContext context = new EntrustTruePassJaspicModule();

        final ServerAuthModule module = (ServerAuthModule) context;
        if (authContextID == null) {
            module.initialize(NON_MANDATORY, NON_MANDATORY, getHandler(), augmentedOptions);
        } else {
            module.initialize(MANDATORY, MANDATORY, getHandler(), augmentedOptions);
        }
        return context;
    }
}
