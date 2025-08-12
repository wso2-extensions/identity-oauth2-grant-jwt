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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Method;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.wso2.carbon.user.core.constants.UserCoreClaimConstants.USERNAME_CLAIM_URI;
import static org.wso2.carbon.user.core.constants.UserCoreClaimConstants.USER_ID_CLAIM_URI;

/**
 * This is a test class for {@link JWTBearerGrantHandler}.
 */
public class JWTBearerGrantHandlerTest {

    private final IdentityProvider residentIdp = new IdentityProvider();
    private final ServiceProvider serviceProvider = new ServiceProvider();
    private final LocalAndOutboundAuthenticationConfig config = new LocalAndOutboundAuthenticationConfig();

    @BeforeClass
    public void setUp() throws Exception {

        residentIdp.setIdentityProviderName("LOCAL");
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(config);
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
}
