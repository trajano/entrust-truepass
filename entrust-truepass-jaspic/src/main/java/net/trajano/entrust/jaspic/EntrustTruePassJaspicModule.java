package net.trajano.entrust.jaspic;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

/**
 * This is a simplified implementation of <a href=
 * "https://github.com/trajano/server-auth-modules/blob/master/src/main/java/net/trajano/auth/HttpHeaderAuthModule.java">HttpHeaderAuthModule</a>
 * where the values are hard coded to the ones required by Entrust TruePass. The
 * content of the user principal would be in the {@code Entrust-Client} HTTP
 * header and it will be Base64 encoded. Implemented as per page 184 of Entrust
 * TruePass Integration Guide.
 * 
 * @see https://trajano.net/2014/06/creating-a-simple-jaspic-auth-module/
 */
public class EntrustTruePassJaspicModule implements
    ServerAuthModule,
    ServerAuthContext {

    /**
     * Constant used by WebSphere credentials.
     */
    private static final String WSCREDENTIAL_SECURITYNAME = "com.ibm.wsspi.security.cred.securityName";

    /**
     * Constant used by WebSphere credentials.
     */
    private static final String WSCREDENTIAL_UNIQUEID = "com.ibm.wsspi.security.cred.uniqueId";

    /**
     * Logger.
     */
    private static final Logger LOG;

    /**
     * Entrust HTTP Header.
     */
    public static final String ENTRUST_HTTP_HEADER = "Entrust-Client";

    static {
        LOG = Logger.getLogger("net.trajano.entrust.jaspic");
    }

    /**
     * Callback handler that is passed in initialize by the container. This
     * processes the callbacks which are objects that populate the "subject".
     */
    private CallbackHandler handler;

    /**
     * Mandatory flag.
     */
    private boolean mandatory;

    private EntrustTruePassPrincipalProvider principalProvider;

    /**
     * WebSphere user. If this is not null then the websphereWorkaounrd would be
     */
    private final String websphereUser;

    public EntrustTruePassJaspicModule(EntrustTruePassPrincipalProvider principalProvider) {
        this(principalProvider, null);
    }

    /**
     * Implements the WebSphere workaround. This requires the
     * {@code webspehereUser} to exist in the user registry of WebSphere.
     *
     * @param client
     *            client subject
     * @param websphereUser
     *            existing WebSphere user name.
     * @param principalName
     *            name that is going to be part of the principal.
     * @throws AuthException
     */
    private void websphereWorkaround(final Subject client,
        String websphereUser,
        String principalName) throws AuthException {

        System.out.println("HERE! " + websphereUser + " " + principalName);
        try {
            final Object userRegistry = Class.forName("com.ibm.wsspi.security.registry.RegistryHelper").getMethod("getUserRegistry", String.class).invoke(null, new Object[] {
                null
            });
            final String uniqueid = (String) userRegistry.getClass().getMethod("getUniqueUserId", String.class).invoke(userRegistry, websphereUser);

            final Hashtable<String, Object> hashtable = new Hashtable<String, Object>();
            hashtable.put(WSCREDENTIAL_UNIQUEID, uniqueid);
            hashtable.put(WSCREDENTIAL_SECURITYNAME, principalName);

            client.getPrivateCredentials().add(hashtable);
        } catch (IllegalAccessException e) {
            throw new AuthException(e.getMessage());
        } catch (InvocationTargetException e) {
            throw new AuthException(e.getMessage());
        } catch (NoSuchMethodException e) {
            throw new AuthException(e.getMessage());
        } catch (ClassNotFoundException e) {
            throw new AuthException(e.getMessage());
        }
    }

    public EntrustTruePassJaspicModule(EntrustTruePassPrincipalProvider principalProvider,
        String websphereUser) {
        this.principalProvider = principalProvider;
        this.websphereUser = websphereUser;
    }

    /**
     * Does nothing.
     *
     * @param messageInfo
     *            message info
     * @param subject
     *            subject
     */
    @Override
    public void cleanSubject(final MessageInfo messageInfo,
        final Subject subject) throws AuthException {

        // Does nothing.
    }

    /**
     * <p>
     * Supported message types. For our case we only need to deal with HTTP
     * servlet request and responses. On Java EE 7 this will handle WebSockets
     * as well.
     * </p>
     * <p>
     * This creates a new array for security at the expense of performance.
     * </p>
     *
     * @return {@link HttpServletRequest} and {@link HttpServletResponse}
     *         classes.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Class[] getSupportedMessageTypes() {

        return new Class<?>[] {
            HttpServletRequest.class,
            HttpServletResponse.class
        };
    }

    /**
     * {@inheritDoc}
     *
     * @param requestPolicy
     *            request policy, ignored
     * @param responsePolicy
     *            response policy, ignored
     * @param h
     *            callback handler
     * @param options
     *            options
     */
    @Override
    public void initialize(final MessagePolicy requestPolicy,
        final MessagePolicy responsePolicy,
        final CallbackHandler h,
        @SuppressWarnings("rawtypes") final Map options) throws AuthException {

        handler = h;
        mandatory = requestPolicy.isMandatory();
    }

    /**
     * Return {@link AuthStatus#SEND_SUCCESS}.
     *
     * @param messageInfo
     *            contains the request and response messages. At this point the
     *            response message is already committed so nothing can be
     *            changed.
     * @param subject
     *            subject.
     * @return {@link AuthStatus#SEND_SUCCESS}
     */
    @Override
    public AuthStatus secureResponse(final MessageInfo messageInfo,
        final Subject subject) throws AuthException {

        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
        final Subject client,
        final Subject serviceSubject)
        throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();
        try {
            if (!mandatory && !req.isSecure()) {
                return AuthStatus.SUCCESS;
            }
            if (!req.isSecure()) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, "An HTTPS connection is required");
                return AuthStatus.SEND_FAILURE;
            }
            final String principalName = "mememe";
            websphereWorkaround(client, websphereUser, principalName);
            return AuthStatus.SUCCESS;
        } catch (final IOException e) {
            LOG.throwing(this.getClass().getName(), "IOException was thrown on validateRequest()", e);
            throw new AuthException(e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    public AuthStatus validateRequest2(final MessageInfo messageInfo,
        final Subject client,
        final Subject serviceSubject)
        throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();
        try {
            if (!mandatory && !req.isSecure()) {
                return AuthStatus.SUCCESS;
            }
            if (!req.isSecure()) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, "An HTTPS connection is required");
                return AuthStatus.SEND_FAILURE;
            }
            String header = req.getHeader(ENTRUST_HTTP_HEADER);
            if (header == null && mandatory) {
                return AuthStatus.FAILURE;
            } else if (header == null && !mandatory) {
                return AuthStatus.SUCCESS;
            }
            final String entrustToken = new String(DatatypeConverter.parseBase64Binary(header));
            final String principalName = principalProvider.getPrincipalNameFromEntrustToken(entrustToken);
            websphereWorkaround(client, websphereUser, principalName);
            return AuthStatus.SUCCESS;
        } catch (final IOException e) {
            LOG.throwing(this.getClass().getName(), "IOException was thrown on validateRequest()", e);
            throw new AuthException(e.getMessage());
        }
    }
}
