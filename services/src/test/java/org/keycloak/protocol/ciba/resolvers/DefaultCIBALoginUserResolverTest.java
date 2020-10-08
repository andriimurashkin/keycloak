package org.keycloak.protocol.ciba.resolvers;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.ciba.CIBAErrorCodes;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.LoginHintToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.DefaultKeycloakContext;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.ws.rs.core.Response;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DefaultCIBALoginUserResolverTest {

    private static final String USERNAME = "username";
    private static final String USER_EMAIL = "joe@email.cz";

    private DefaultCIBALoginUserResolver defaultCIBALoginUserResolver;

    @Mock
    private KeycloakSession keycloakSession;
    @Mock
    private RealmModel realmModelMock;
    @Mock
    private UserProvider userProvider;
    private UserModel userModel;

    @Before
    public void setUp() {
        keycloakSession = new DefaultKeycloakSession(null) {
            @Override
            public UserProvider users() {
                return userProvider;
            }

            @Override
            public KeycloakContext getContext() {
                return getKeycloakContext(this);
            }
        };
        defaultCIBALoginUserResolver = new DefaultCIBALoginUserResolver(keycloakSession);
        userModel = getUserModel();
    }

    @Test
    public void getUserFromLoginHint() {
        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(userModel);

        UserModel actual = defaultCIBALoginUserResolver.getUserFromLoginHint(USERNAME);

        assertEquals(userModel, actual);

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByUsername(USERNAME, realmModelMock);
    }

    @Test
    public void getUserFromLoginHint_userModelNotFound() {
        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(null);

        try {
            defaultCIBALoginUserResolver.getUserFromLoginHint(USERNAME);
            fail();
        } catch (ErrorResponseException e) {
            assertEquals(CIBAErrorCodes.UNKNOWN_USER_ID, ((OAuth2ErrorRepresentation) e.getResponse().getEntity()).getError());
            assertEquals("no user found", e.getErrorDescription());
            assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo().toEnum());
        }

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByUsername(USERNAME, realmModelMock);
    }

    @Test
    public void getUserFromIdTokenHint_email() throws NoSuchAlgorithmException {
        IDToken idToken = new IDToken();
        idToken.setEmail(USER_EMAIL);
        idToken.setPreferredUsername(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(true);
        when(userProvider.getUserByEmail(USER_EMAIL, realmModelMock)).thenReturn(userModel);

        UserModel actual = defaultCIBALoginUserResolver.getUserFromIdTokenHint(getEncodedToken(idToken));

        assertEquals(userModel, actual);

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByEmail(USER_EMAIL, realmModelMock);
    }

    @Test
    public void getUserFromIdTokenHint_username() throws NoSuchAlgorithmException {
        IDToken idToken = new IDToken();
        idToken.setPreferredUsername(USERNAME);
        idToken.setEmail(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(userModel);

        UserModel actual = defaultCIBALoginUserResolver.getUserFromIdTokenHint(getEncodedToken(idToken));

        assertEquals(userModel, actual);

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByUsername(USERNAME, realmModelMock);
    }

    @Test
    public void getUserFromIdTokenHint_userNotFoundError() throws NoSuchAlgorithmException {
        IDToken idToken = new IDToken();
        idToken.setPreferredUsername(USERNAME);
        idToken.setEmail(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(null);

        try {
            defaultCIBALoginUserResolver.getUserFromIdTokenHint(getEncodedToken(idToken));
            fail();
        } catch (ErrorResponseException e) {
            assertEquals(CIBAErrorCodes.UNKNOWN_USER_ID, ((OAuth2ErrorRepresentation) e.getResponse().getEntity()).getError());
            assertEquals("no user found", e.getErrorDescription());
            assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo().toEnum());
        }

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByUsername(USERNAME, realmModelMock);
    }

    @Test
    public void getUserFromIdTokenHint_invalidTokenError() {
        try {
            defaultCIBALoginUserResolver.getUserFromIdTokenHint("invalid_token");
            fail();
        } catch (ErrorResponseException e) {
            assertEquals(CIBAErrorCodes.INVALID_REQUEST, ((OAuth2ErrorRepresentation) e.getResponse().getEntity()).getError());
            assertEquals("token invalid", e.getErrorDescription());
            assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo().toEnum());
        }

        verify(realmModelMock, never()).isLoginWithEmailAllowed();
        verify(userProvider, never()).getUserByEmail(anyString(), any());
    }

    @Test
    public void getUserFromLoginHintToken_username() throws NoSuchAlgorithmException {
        LoginHintToken token = new LoginHintToken();
        token.setPreferredUsername(USERNAME);
        token.setEmail(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(userModel);

        UserModel actual = defaultCIBALoginUserResolver.getUserFromLoginHintToken(getEncodedToken(token));

        assertEquals(userModel, actual);

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider, never()).getUserByEmail(anyString(), any());
    }

    @Test
    public void getUserFromLoginHintToken_email() throws NoSuchAlgorithmException {
        LoginHintToken token = new LoginHintToken();
        token.setPreferredUsername(USER_EMAIL);
        token.setEmail(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(true);
        when(userProvider.getUserByEmail(USER_EMAIL, realmModelMock)).thenReturn(userModel);

        UserModel actual = defaultCIBALoginUserResolver.getUserFromLoginHintToken(getEncodedToken(token));

        assertEquals(userModel, actual);

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByEmail(USER_EMAIL, realmModelMock);
    }

    @Test
    public void getUserFromLoginHintToken_userNotFoundError() throws NoSuchAlgorithmException {
        LoginHintToken token = new LoginHintToken();
        token.setPreferredUsername(USERNAME);
        token.setEmail(USER_EMAIL);

        when(realmModelMock.isLoginWithEmailAllowed()).thenReturn(false);
        when(userProvider.getUserByUsername(USERNAME, realmModelMock)).thenReturn(null);

        try {
            defaultCIBALoginUserResolver.getUserFromLoginHintToken(getEncodedToken(token));
            fail();
        } catch (ErrorResponseException e) {
            assertEquals(CIBAErrorCodes.UNKNOWN_USER_ID, ((OAuth2ErrorRepresentation) e.getResponse().getEntity()).getError());
            assertEquals("no user found", e.getErrorDescription());
            assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo().toEnum());
        }

        verify(realmModelMock).isLoginWithEmailAllowed();
        verify(userProvider).getUserByUsername(USERNAME, realmModelMock);
    }

    @Test
    public void getUserFromLoginHintToken_invalidTokenError() {
        try {
            defaultCIBALoginUserResolver.getUserFromLoginHintToken("invalid_token");
            fail();
        } catch (ErrorResponseException e) {
            assertEquals(CIBAErrorCodes.INVALID_REQUEST, ((OAuth2ErrorRepresentation) e.getResponse().getEntity()).getError());
            assertEquals("token invalid", e.getErrorDescription());
            assertEquals(Response.Status.BAD_REQUEST, e.getResponse().getStatusInfo().toEnum());
        }

        verify(realmModelMock, never()).isLoginWithEmailAllowed();
        verify(userProvider, never()).getUserByEmail(anyString(), any());
    }

    private <T extends JsonWebToken> String getEncodedToken(T idToken) throws NoSuchAlgorithmException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        return new JWSBuilder()
                       .jsonContent(idToken)
                       .rsa256(keyPair.getPrivate());
    }

    private UserModel getUserModel() {
        return new AbstractUserAdapter(keycloakSession, realmModelMock, new ComponentModel()) {
            @Override
            public String getUsername() {
                return USERNAME;
            }
        };
    }

    private DefaultKeycloakContext getKeycloakContext(KeycloakSession keycloakSession) {
        DefaultKeycloakContext keycloakContext = new DefaultKeycloakContext(keycloakSession) {

        };
        keycloakContext.setRealm(realmModelMock);
        return keycloakContext;
    }
}