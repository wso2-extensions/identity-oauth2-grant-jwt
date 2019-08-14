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

import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.when;

/**
 * This is a test class for {@link JWTBearerGrantHandler}.
 */
@PrepareForTest({ ClaimsUtil.class, OAuthServerConfiguration.class })
public class JWTBearerGrantHandlerTest {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @SuppressWarnings("unchecked")
    @Test(description = "This method is used to check and convert the custom claims to custom claim string map format",
            dataProvider = "customClaimDataProvider", dependsOnMethods = "testHandleCustomClaims")
    public void testCustomClaims(Map<String, Object> customClaims) {

        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
        OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOauthServerConfig);
        when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);
        JWTBearerGrantHandler jwtBearerGrantHandler = new JWTBearerGrantHandler();
        Map<String, String> customClaimsMap = jwtBearerGrantHandler.getCustomClaims(customClaims);

        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            Assert.assertEquals(customClaimsMap.get(entry.getKey()), entry.getValue().toString(),
                    "Custom claim map " + "creation failed");
        }
    }

    @SuppressWarnings("unchecked")
    @Test(description = "This method tests whether handling custom claims is happening as expected", dataProvider =
            "customClaimDataProvider")
    public void testHandleCustomClaims(Map<String, Object> customClaims) throws IdentityException,
            IdentityApplicationManagementException {

        PowerMockito.mockStatic(ClaimsUtil.class);
        when(ClaimsUtil.handleClaimMapping(Mockito.any(IdentityProvider.class), Mockito.anyMap(), Mockito.anyString(),
                Mockito.any(OAuthTokenReqMessageContext.class))).thenAnswer(new Answer<Map>() {
            @Override public Map answer(InvocationOnMock invocationOnMock) {
                return (Map) invocationOnMock.getArguments()[1];
            }
        });

        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        OAuthServerConfiguration mockOauthServerConfig = Mockito.mock(OAuthServerConfiguration.class);
        OauthTokenIssuer identityOauthTokenIssuer = Mockito.mock(OauthTokenIssuer.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOauthServerConfig);
        when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(identityOauthTokenIssuer);
        JWTBearerGrantHandler jwtBearerGrantHandler = new JWTBearerGrantHandler();

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = Mockito.mock(OAuthTokenReqMessageContext.class);
        IdentityProvider identityProvider = new IdentityProvider();
        AuthenticatedUser user = new AuthenticatedUser();
        oAuthTokenReqMessageContext.setAuthorizedUser(user);
        Mockito.doReturn(user).when(oAuthTokenReqMessageContext).getAuthorizedUser();
        Mockito.doCallRealMethod().when(oAuthTokenReqMessageContext)
                .setAuthorizedUser(Mockito.any(AuthenticatedUser.class));

        jwtBearerGrantHandler.handleCustomClaims(oAuthTokenReqMessageContext, customClaims, identityProvider);

        Assert.assertNotNull(oAuthTokenReqMessageContext.getAuthorizedUser(),
                "After setting custom claims authorized" + " user is null");
        Assert.assertEquals(oAuthTokenReqMessageContext.getAuthorizedUser().getUserAttributes().size(), 2,
                "Relevant " + "custom claims are not added to the authorized user");
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
}
