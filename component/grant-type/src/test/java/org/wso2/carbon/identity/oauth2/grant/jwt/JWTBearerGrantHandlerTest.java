/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.oauth2.grant.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.wso2.carbon.user.core.constants.UserCoreClaimConstants.USERNAME_CLAIM_URI;
import static org.wso2.carbon.user.core.constants.UserCoreClaimConstants.USER_ID_CLAIM_URI;

/**
 * This is a test class for {@link JWTBearerGrantHandler}.
 */
@WithCarbonHome
public class JWTBearerGrantHandlerTest {

    static {
        if (System.getProperty("carbon.home") == null) {
            System.setProperty("carbon.home", Paths.get(System.getProperty("user.dir"), "target").toString());
        }
    }

    private final IdentityProvider residentIdp = new IdentityProvider();
    private final ServiceProvider serviceProvider = new ServiceProvider();
    private final LocalAndOutboundAuthenticationConfig config = new LocalAndOutboundAuthenticationConfig();
    private KeyPair keyPair;
    private static final String TEST_TOKEN_ENDPOINT_ALIAS = "https://localhost:9443/oauth2/token";
    private static final String TEST_CLIENT_ID = "client1";
    private static final String TEST_USERNAME = "testuser";

    @BeforeClass
    public void setUp() throws Exception {

        residentIdp.setIdentityProviderName("LOCAL");
        residentIdp.setEnable(true);

        FederatedAuthenticatorConfig oidcAuth = new FederatedAuthenticatorConfig();
        oidcAuth.setName(IdentityApplicationConstants.Authenticator.OIDC.NAME);
        Property tokenUrlProp = new Property();
        tokenUrlProp.setName(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
        tokenUrlProp.setValue(TEST_TOKEN_ENDPOINT_ALIAS);
        oidcAuth.setProperties(new Property[]{tokenUrlProp});
        residentIdp.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{oidcAuth});

        serviceProvider.setLocalAndOutBoundAuthenticationConfig(config);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        keyPair = keyPairGen.generateKeyPair();
    }

    @Test(description = "This method is used to check and convert the custom claims to custom claim string map format",
            dataProvider = "customClaimDataProvider", dependsOnMethods = "testHandleCustomClaims")
    public void testCustomClaims(Map<String, Object> customClaims) {

        try (MockedStatic<OAuthServerConfiguration> mockedOAuthConfig =
                     Mockito.mockStatic(OAuthServerConfiguration.class)) {

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);

            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);

            JWTBearerGrantHandler jwtBearerGrantHandler = new JWTBearerGrantHandler();
            Map<String, String> customClaimsMap = jwtBearerGrantHandler.getCustomClaims(customClaims);

            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                Assert.assertEquals(customClaimsMap.get(entry.getKey()), entry.getValue().toString(),
                        "Custom claim map creation failed");
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Test(description = "This method tests whether handling custom claims is happening as expected", dataProvider =
            "customClaimDataProvider")
    public void testHandleCustomClaims(Map<String, Object> customClaims) throws IdentityException,
            IdentityApplicationManagementException {

        try (MockedStatic<ClaimsUtil> mockedClaimsUtil = Mockito.mockStatic(ClaimsUtil.class);
                MockedStatic<OAuthServerConfiguration> mockedOAuthConfig =
                        Mockito.mockStatic(OAuthServerConfiguration.class)) {

            mockedClaimsUtil.when(() -> ClaimsUtil.handleClaimMapping(
                    Mockito.any(IdentityProvider.class),
                    Mockito.anyMap(),
                    anyString(),
                    Mockito.any(OAuthTokenReqMessageContext.class),
                    Mockito.anyBoolean()
            )).thenAnswer(new Answer<Map<String, String>>() {
                @Override
                @SuppressWarnings("unchecked")
                public Map<String, String> answer(InvocationOnMock invocationOnMock) {
                    return (Map<String, String>) invocationOnMock.getArguments()[1];
                }
            });

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);

            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);

            JWTBearerGrantHandler jwtBearerGrantHandler = new JWTBearerGrantHandler();

            OAuthTokenReqMessageContext oAuthTokenReqMessageContext = Mockito.mock(OAuthTokenReqMessageContext.class);
            IdentityProvider identityProvider = new IdentityProvider();
            AuthenticatedUser user = new AuthenticatedUser();

            Mockito.doReturn(user).when(oAuthTokenReqMessageContext).getAuthorizedUser();
            Mockito.doCallRealMethod().when(oAuthTokenReqMessageContext).setAuthorizedUser(Mockito.any(AuthenticatedUser.class));

            jwtBearerGrantHandler.handleCustomClaims(oAuthTokenReqMessageContext, customClaims, identityProvider);

            Assert.assertNotNull(oAuthTokenReqMessageContext.getAuthorizedUser(),
                    "After setting custom claims authorized user is null");
        }
    }

    @SuppressWarnings("unchecked")
    @DataProvider(name = "customClaimDataProvider")
    public Object[][] provideClaimSetData() {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("claim1", "test");
        customClaims.put("claim2", new ArrayList() {{
            add("claim2");
            add("claim1");
        }});
        return new Object[][]{{customClaims}};
    }

    /**
     * Test resolveLocalUsername method - Token exchange disabled
     */
    @Test(description = "Test resolveLocalUsername when token exchange is disabled")
    public void testResolveLocalUsernameTokenExchangeDisabled() throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<OAuthServerConfiguration> mockedOAuthConfig
                     = Mockito.mockStatic(OAuthServerConfiguration.class)) {

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);

            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                "OAuth.JWTGrant.EnableTokenExchangeForLocalUsersWithResidentIdP"))
                .thenReturn("false");

            JWTBearerGrantHandler handler = new JWTBearerGrantHandler();
            String result = (String) mockedResolveLocalUserNameMethod(handler).invoke(
                    handler, "client1", "user1", residentIdp);
            Assert.assertEquals(result, "user1", "Should return subject as is when token exchange is disabled");
        }
    }

    /**
     * Test resolveLocalUsername method - Username subject with existing user
     */
    @Test(description = "Test resolveLocalUsername for username subject with existing user")
    public void testResolveLocalUsernameUsernameSubject() throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuthServerConfiguration> mockedOAuthConfig
                     = Mockito.mockStatic(OAuthServerConfiguration.class)) {

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);

            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                "OAuth.JWTGrant.EnableTokenExchangeForLocalUsersWithResidentIdP"))
                .thenReturn("true");

            config.setSubjectClaimUri(USERNAME_CLAIM_URI);
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                .thenReturn(serviceProvider);

            mockedOAuth2Util.when(() -> OAuth2Util.isExistingUser(anyString(), anyString()))
                .thenReturn(true);

            JWTBearerGrantHandler handler = new JWTBearerGrantHandler();
            String result = (String) mockedResolveLocalUserNameMethod(handler).invoke(
                    handler, "client1", "testuser", residentIdp);
            Assert.assertEquals(result, "testuser", "Should return the existing username");
        }
    }

    /**
     * Test resolveLocalUsername method - User ID subject with successful resolution
     */
    @Test(description = "Test resolveLocalUsername for user ID subject")
    public void testResolveLocalUsernameUserIdSubject() throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuthServerConfiguration> mockedOAuthConfig
                     = Mockito.mockStatic(OAuthServerConfiguration.class)) {

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);

            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                "OAuth.JWTGrant.EnableTokenExchangeForLocalUsersWithResidentIdP"))
                .thenReturn("true");

            config.setSubjectClaimUri(USER_ID_CLAIM_URI);
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                .thenReturn(serviceProvider);

            // Mock user ID resolution
            mockedOAuth2Util.when(() -> OAuth2Util.getUserStoreDomainFromUserId(anyString()))
                .thenReturn("TEST");
            mockedOAuth2Util.when(() -> OAuth2Util.resolveUsernameFromUserId(anyString(), anyString()))
                .thenReturn("resolveduser");
            mockedOAuth2Util.when(() -> OAuth2Util.isExistingUser(anyString(), anyString()))
                .thenReturn(true);

            JWTBearerGrantHandler handler = new JWTBearerGrantHandler();
            String result = (String) mockedResolveLocalUserNameMethod(handler).invoke(
                    handler, "client1", "TEST/testUserId@carbon.super", residentIdp);
            Assert.assertEquals(result, "TEST/resolveduser@carbon.super",
                "Should return fully qualified username for user ID subject");
        }
    }

    private Method mockedResolveLocalUserNameMethod(JWTBearerGrantHandler handler) throws Exception {

        java.lang.reflect.Field tenantDomainField = JWTBearerGrantHandler.class.getDeclaredField("tenantDomain");
        tenantDomainField.setAccessible(true);
        tenantDomainField.set(handler, "carbon.super");

        Method resolveLocalUsernameMethod = JWTBearerGrantHandler.class
                .getDeclaredMethod("resolveLocalUsername", String.class, String.class, IdentityProvider.class);
        resolveLocalUsernameMethod.setAccessible(true);

        return resolveLocalUsernameMethod;
    }

    @Test(description = "Test validateGrant for active local user with resident IdP")
    public void testValidateGrantWithActiveLocalUser() throws Exception {

        AccountLockService mockAccountLockService = Mockito.mock(AccountLockService.class);
        AccountDisableService mockAccountDisableService = Mockito.mock(AccountDisableService.class);
        Mockito.when(mockAccountLockService.isAccountLocked(anyString(), anyString(), anyString())).thenReturn(false);
        Mockito.when(mockAccountDisableService.isAccountDisabled(anyString(), anyString(), anyString())).thenReturn(false);

        executeValidateGrantScenario(mockAccountLockService, mockAccountDisableService, true, residentIdp);
    }

    @Test(description = "Test validateGrant fails for locked local user with resident IdP",
            expectedExceptions = IdentityOAuth2ClientException.class)
    public void testValidateGrantWithLockedLocalUser() throws Exception {

        AccountLockService mockAccountLockService = Mockito.mock(AccountLockService.class);
        AccountDisableService mockAccountDisableService = Mockito.mock(AccountDisableService.class);
        Mockito.when(mockAccountLockService.isAccountLocked(anyString(), anyString(), anyString())).thenReturn(true);

        try {
            executeValidateGrantScenario(mockAccountLockService, mockAccountDisableService, true, residentIdp);
        } catch (IdentityOAuth2ClientException e) {
            Assert.assertEquals(e.getErrorCode(), UserCoreConstants.ErrorCode.USER_IS_LOCKED);
            throw e;
        }
    }

    @Test(description = "Test validateGrant fails for disabled local user with resident IdP",
            expectedExceptions = IdentityOAuth2ClientException.class)
    public void testValidateGrantWithDisabledLocalUser() throws Exception {

        AccountLockService mockAccountLockService = Mockito.mock(AccountLockService.class);
        AccountDisableService mockAccountDisableService = Mockito.mock(AccountDisableService.class);
        Mockito.when(mockAccountLockService.isAccountLocked(anyString(), anyString(), anyString())).thenReturn(false);
        Mockito.when(mockAccountDisableService.isAccountDisabled(anyString(), anyString(), anyString())).thenReturn(true);

        try {
            executeValidateGrantScenario(mockAccountLockService, mockAccountDisableService, true, residentIdp);
        } catch (IdentityOAuth2ClientException e) {
            Assert.assertEquals(e.getErrorCode(), IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE);
            throw e;
        }
    }

    @Test(description = "Test validateGrant for federated user bypasses account state validation")
    public void testValidateGrantWithFederatedUser() throws Exception {

        AccountLockService mockAccountLockService = Mockito.mock(AccountLockService.class);
        AccountDisableService mockAccountDisableService = Mockito.mock(AccountDisableService.class);

        IdentityProvider federatedIdp = new IdentityProvider();
        federatedIdp.setIdentityProviderName("FederatedIdP");
        federatedIdp.setAlias(TEST_TOKEN_ENDPOINT_ALIAS);
        federatedIdp.setEnable(true);

        executeValidateGrantScenario(mockAccountLockService, mockAccountDisableService, false, federatedIdp);

        Mockito.verifyNoInteractions(mockAccountLockService);
        Mockito.verifyNoInteractions(mockAccountDisableService);
    }

    private void executeValidateGrantScenario(AccountLockService mockAccountLockService,
                                              AccountDisableService mockAccountDisableService,
                                              boolean enableTokenExchange,
                                              IdentityProvider idp) throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuthServerConfiguration> mockedOAuthConfig = Mockito.mockStatic(OAuthServerConfiguration.class);
             MockedStatic<IdentityProviderManager> mockedIdpManager = Mockito.mockStatic(IdentityProviderManager.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedComponentHolder = Mockito.mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<FrameworkUtils> mockedFrameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
            OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);
            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
            Mockito.when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);
            Mockito.when(mockOauthServerConfig.getTimeStampSkewInSeconds()).thenReturn(0L);

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    "OAuth.JWTGrant.EnableTokenExchangeForLocalUsersWithResidentIdP"))
                    .thenReturn(String.valueOf(enableTokenExchange));
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty("EnforceCertificateValidity"))
                    .thenReturn("false");

            IdentityProviderManager mockIdpMgtInstance = Mockito.mock(IdentityProviderManager.class);
            mockedIdpManager.when(IdentityProviderManager::getInstance).thenReturn(mockIdpMgtInstance);
            Mockito.when(mockIdpMgtInstance.getIdPByMetadataProperty(anyString(), anyString(), anyString(), Mockito.anyBoolean()))
                    .thenReturn(idp);
            Mockito.when(mockIdpMgtInstance.getIdPByName(anyString(), anyString())).thenReturn(idp);
            Mockito.when(mockIdpMgtInstance.getResidentIdP(anyString())).thenReturn(residentIdp);

            config.setSubjectClaimUri(USERNAME_CLAIM_URI);
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);
            mockedOAuth2Util.when(() -> OAuth2Util.isExistingUser(anyString(), anyString()))
                    .thenReturn(true);

            AuthenticatedUser localUser = new AuthenticatedUser();
            localUser.setUserName(TEST_USERNAME);
            localUser.setTenantDomain("carbon.super");
            localUser.setUserStoreDomain("PRIMARY");
            mockedOAuth2Util.when(() -> OAuth2Util.getUserFromUserName(anyString())).thenReturn(localUser);

            mockedComponentHolder.when(OAuth2ServiceComponentHolder::getAccountLockService)
                    .thenReturn(mockAccountLockService);
            mockedComponentHolder.when(OAuth2ServiceComponentHolder::getAccountDisableService)
                    .thenReturn(mockAccountDisableService);

            Property accountDisableProp = new Property();
            accountDisableProp.setName(FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY);
            accountDisableProp.setValue("true");
            mockedFrameworkUtils.when(() -> FrameworkUtils.getResidentIdpConfiguration(
                    FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, "carbon.super"))
                    .thenReturn(accountDisableProp);

            X509Certificate mockCert = Mockito.mock(X509Certificate.class);
            Mockito.when(mockCert.getPublicKey()).thenReturn(keyPair.getPublic());

            JWTBearerGrantHandler handler = createTestGrantHandler(mockCert);
            String assertion = createSignedJWTAssertion(
                    TEST_TOKEN_ENDPOINT_ALIAS, TEST_USERNAME, TEST_TOKEN_ENDPOINT_ALIAS, TEST_CLIENT_ID);
            OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext(assertion);

            boolean isValid = handler.validateGrant(tokReqMsgCtx);
            Assert.assertTrue(isValid, "validateGrant should return true for valid assertion and active user");
        }
    }

    private String createSignedJWTAssertion(String issuer, String subject, String audience, String azp) throws Exception {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000));
        if (azp != null) {
            builder.claim("azp", azp);
        }
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
        signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));
        return signedJWT.serialize();
    }

    private OAuthTokenReqMessageContext createTokenReqMessageContext(String assertion) {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setTenantDomain("carbon.super");
        tokenReqDTO.setScope(new String[]{"openid"});
        tokenReqDTO.setRequestParameters(new RequestParameter[]{
                new RequestParameter(JWTConstants.OAUTH_JWT_ASSERTION, assertion)
        });
        return new OAuthTokenReqMessageContext(tokenReqDTO);
    }

    private JWTBearerGrantHandler createTestGrantHandler(X509Certificate mockCert) {

        return new JWTBearerGrantHandler() {
            @Override
            protected X509Certificate resolveSignerCertificate(JWSHeader header, IdentityProvider idp) {
                return mockCert;
            }

            @Override
            protected void handleCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx,
                                              Map<String, Object> customClaims,
                                              IdentityProvider idp) {
                // no-op for validateGrant unit testing
            }
        };
    }
}
