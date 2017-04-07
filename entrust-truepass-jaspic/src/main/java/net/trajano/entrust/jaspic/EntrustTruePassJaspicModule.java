package net.trajano.entrust.jaspic;

import net.trajano.entrust.jaspic.internal.Base64;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
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
     * Resource bundle.
     */
    private static final ResourceBundle R;

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
     * Builds a list of groups from the request. This simply returns "users"
     *
     * @param req
     *            servlet request.
     * @return array of groups.
     */
    private String[] groups(final HttpServletRequest req) {

        return new String[] {
            "users"
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
        final Subject serviceSubject) throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();
        try {
            if (!mandatory && !req.isSecure()) {
                return AuthStatus.SUCCESS;
            }
            if (!req.isSecure()) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, R.getString("SSLReq"));
                return AuthStatus.SEND_FAILURE;
            }
            final String userName = Base64.decodeToString(req.getHeader(ENTRUST_HTTP_HEADER));
            if (userName == null && mandatory) {
                return AuthStatus.FAILURE;
            } else if (userName == null && !mandatory) {
                return AuthStatus.SUCCESS;
            }

            handler.handle(new Callback[] {
                new CallerPrincipalCallback(client, userName),
                new GroupPrincipalCallback(client, groups(req))
            });
            return AuthStatus.SUCCESS;
        } catch (final IOException e) {
            LOG.throwing(this.getClass()
                .getName(), "Exception was thrown on validateRequest()", e);
            throw new AuthException(e.getMessage());
        } catch (final UnsupportedCallebackException e) {
            LOG.throwing(this.getClass()
                .getName(), "Exception was thrown on validateRequest()", e);
            throw new AuthException(e.getMessage());
        }
    }
}
