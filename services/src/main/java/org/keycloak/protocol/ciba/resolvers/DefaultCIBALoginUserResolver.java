package org.keycloak.protocol.ciba.resolvers;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.CIBAErrorCodes;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.LoginHintToken;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.core.Response;

public class DefaultCIBALoginUserResolver implements CIBALoginUserResolver {

    private static final Logger logger = Logger.getLogger(DefaultCIBALoginUserResolver.class);

    private final KeycloakSession session;

    public DefaultCIBALoginUserResolver(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public UserModel getUserFromLoginHint(String loginHint) {
        UserModel userModel = KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), loginHint);
        if (userModel == null) {
            throw new ErrorResponseException(CIBAErrorCodes.UNKNOWN_USER_ID, "no user found", Response.Status.BAD_REQUEST);
        }
        return userModel;
    }

    @Override
    public UserModel getUserFromLoginHintToken(String loginHintToken) {
        try {
            JWSInput input = new JWSInput(loginHintToken);
            LoginHintToken token = input.readJsonContent(LoginHintToken.class);

            String username = StringUtils.isNotBlank(token.getPreferredUsername()) ? token.getPreferredUsername() : token.getEmail();
            UserModel userModel = KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), username);
            if (userModel == null) {
                throw new ErrorResponseException(CIBAErrorCodes.UNKNOWN_USER_ID, "no user found", Response.Status.BAD_REQUEST);
            }
            return userModel;
        } catch (JWSInputException e) {
            logger.warn("Failed verify user hint token", e);
            throw new ErrorResponseException(CIBAErrorCodes.INVALID_REQUEST, "token invalid", Response.Status.BAD_REQUEST);
        }
    }

    @Override
    public UserModel getUserFromIdTokenHint(String idTokenHint) {
        try {
            JWSInput input = new JWSInput(idTokenHint);
            IDToken token = input.readJsonContent(IDToken.class);

            String username = StringUtils.isNotBlank(token.getPreferredUsername()) ? token.getPreferredUsername() : token.getEmail();
            UserModel userModel = KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), username);
            if (userModel == null) {
                throw new ErrorResponseException(CIBAErrorCodes.UNKNOWN_USER_ID, "no user found", Response.Status.BAD_REQUEST);
            }
            return userModel;
        } catch (JWSInputException e) {
            logger.warn("Failed verify id token", e);
            throw new ErrorResponseException(CIBAErrorCodes.INVALID_REQUEST, "token invalid", Response.Status.BAD_REQUEST);
        }
    }

    @Override
    public String getInfoUsedByAuthentication(UserModel user) {
        return user.getUsername();
    }

    @Override
    public UserModel getUserFromInfoUsedByAuthentication(String info) {
        return KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), info);
    }

    @Override
    public void close() {
    }

}
