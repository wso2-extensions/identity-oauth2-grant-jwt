/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.grant.jwt;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests the account state validation of {@link JWTBearerGrantHandler}.
 */
public class JWTBearerGrantHandlerAccountStateTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USERNAME = "jwtuser";
    private static final String USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    private static final String FEDERATED_IDP_NAME = "jwt-bearer-issuer";
    private static final String LOCKED_MESSAGE = "17003 Account is locked for user jwtuser in user store PRIMARY " +
            "in tenant carbon.super. Cannot login until the account is unlocked.";
    private static final String DISABLED_MESSAGE = "17004 Account is disabled for user: jwtuser in user store: " +
            "PRIMARY in tenant: carbon.super. Cannot login until the account is enabled.";

    private JWTBearerGrantHandler jwtBearerGrantHandler;
    private AccountLockService accountLockService;
    private AccountDisableService accountDisableService;
    private FederatedAssociationManager federatedAssociationManager;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        oAuthServerConfiguration = Mockito.mockStatic(OAuthServerConfiguration.class);
        OAuthServerConfiguration mockOauthServerConfig = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOauthServerConfig);
        when(mockOauthServerConfig.getIdentityOauthTokenIssuer()).thenReturn(mock(OauthTokenIssuer.class));

        // Used to resolve the primary user store domain name.
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(realmConfiguration.getUserStoreProperty("DomainName")).thenReturn("PRIMARY");
        RealmService realmService = mock(RealmService.class);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);

        accountLockService = mock(AccountLockService.class);
        accountDisableService = mock(AccountDisableService.class);
        OAuth2ServiceComponentHolder.setAccountLockService(accountLockService);
        OAuth2ServiceComponentHolder.setAccountDisableService(accountDisableService);

        oAuth2Util = Mockito.mockStatic(OAuth2Util.class);
        federatedAssociationManager = mock(FederatedAssociationManager.class);
        frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getFederatedAssociationManager).thenReturn(federatedAssociationManager);
        mockAccountDisablingEnabled(true);

        jwtBearerGrantHandler = new JWTBearerGrantHandler();
        Field tenantDomainField = JWTBearerGrantHandler.class.getDeclaredField("tenantDomain");
        tenantDomainField.setAccessible(true);
        tenantDomainField.set(jwtBearerGrantHandler, TENANT_DOMAIN);
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfiguration.close();
        oAuth2Util.close();
        frameworkUtils.close();
        identityTenantUtil.close();
        OAuth2ServiceComponentHolder.setAccountLockService(null);
        OAuth2ServiceComponentHolder.setAccountDisableService(null);
    }

    @DataProvider(name = "rejectedAccountStateProvider")
    public Object[][] rejectedAccountStateProvider() {

        return new Object[][]{
                // subject, locked, disabled, expected error message
                {USERNAME, true, false, LOCKED_MESSAGE},
                {USERNAME, false, true, DISABLED_MESSAGE},
                {USERNAME, true, true, LOCKED_MESSAGE},
                {"SECONDARY/" + USERNAME, true, false, LOCKED_MESSAGE.replace("PRIMARY", "SECONDARY")},
                {"SECONDARY/" + USERNAME, false, true, DISABLED_MESSAGE.replace("PRIMARY", "SECONDARY")},
        };
    }

    @Test(dataProvider = "rejectedAccountStateProvider")
    public void testLockedOrDisabledLocalUserIsRejected(String subject, boolean locked, boolean disabled,
                                                        String expectedErrorMessage) throws Exception {

        mockLocalUser(subject, locked, disabled);
        try {
            jwtBearerGrantHandler.validateAccountState(getResidentIdP(), subject);
            Assert.fail("Grant should be rejected for a locked or disabled user.");
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(), expectedErrorMessage);
            // Error code must stay null so that the token endpoint responds with invalid_grant.
            Assert.assertNull(e.getErrorCode());
        }
    }

    @Test
    public void testActiveLocalUserIsAllowed() throws Exception {

        mockLocalUser(USERNAME, false, false);
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME);
    }

    @Test
    public void testDisabledUserIsAllowedWhenAccountDisablingIsNotEnabled() throws Exception {

        mockAccountDisablingEnabled(false);
        mockLocalUser(USERNAME, false, true);
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME);
        verify(accountDisableService, never()).isAccountDisabled(anyString(), anyString(), anyString());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class, expectedExceptionsMessageRegExp = "17003 .*")
    public void testTenantQualifiedSubjectIsResolved() throws Exception {

        mockLocalUser(USERNAME, true, false);
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME + "@" + TENANT_DOMAIN);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class, expectedExceptionsMessageRegExp = "17003 .*")
    public void testUserIdSubjectOfResidentIdPIsResolved() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.isExistingUser(USER_ID, TENANT_DOMAIN)).thenReturn(false);
        oAuth2Util.when(() -> OAuth2Util.resolveUsernameFromUserId(TENANT_DOMAIN, USER_ID)).thenReturn(USERNAME);
        when(accountLockService.isAccountLocked(USERNAME, TENANT_DOMAIN, "PRIMARY")).thenReturn(true);
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USER_ID);
    }

    @Test
    public void testSubjectWithoutLocalAccountIsAllowed() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.isExistingUser(anyString(), anyString())).thenReturn(false);
        jwtBearerGrantHandler.validateAccountState(getFederatedIdP(), "federated-only-user");
        verify(accountLockService, never()).isAccountLocked(anyString(), anyString(), anyString());
        verify(accountDisableService, never()).isAccountDisabled(anyString(), anyString(), anyString());
        // Only subjects of the resident IdP are resolved as user IDs.
        oAuth2Util.verify(() -> OAuth2Util.resolveUsernameFromUserId(anyString(), anyString()), never());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class, expectedExceptionsMessageRegExp = "17003 .*")
    public void testLockedAssociatedLocalUserOfFederatedSubjectIsRejected() throws Exception {

        String federatedSubject = "fed-subject-123";
        when(federatedAssociationManager.getUserForFederatedAssociation(TENANT_DOMAIN, FEDERATED_IDP_NAME,
                federatedSubject)).thenReturn("PRIMARY/" + USERNAME);
        when(accountLockService.isAccountLocked(USERNAME, TENANT_DOMAIN, "PRIMARY")).thenReturn(true);
        jwtBearerGrantHandler.validateAccountState(getFederatedIdP(), federatedSubject);
    }

    @Test
    public void testFederatedAssociationIsNotLookedUpForResidentIdP() throws Exception {

        mockLocalUser(USERNAME, false, false);
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME);
        verify(federatedAssociationManager, never())
                .getUserForFederatedAssociation(anyString(), anyString(), anyString());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testUserStoreErrorIsPropagated() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.isExistingUser(USERNAME, TENANT_DOMAIN))
                .thenThrow(new UserStoreException("error"));
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testAccountLockServiceErrorIsPropagated() throws Exception {

        mockLocalUser(USERNAME, false, false);
        when(accountLockService.isAccountLocked(USERNAME, TENANT_DOMAIN, "PRIMARY"))
                .thenThrow(new AccountLockServiceException("error"));
        jwtBearerGrantHandler.validateAccountState(getResidentIdP(), USERNAME);
    }

    private void mockLocalUser(String username, boolean locked, boolean disabled) throws Exception {

        String userStoreDomain = username.contains("/") ? username.split("/")[0] : "PRIMARY";
        String domainFreeUsername = username.contains("/") ? username.split("/")[1] : username;
        oAuth2Util.when(() -> OAuth2Util.isExistingUser(username, TENANT_DOMAIN)).thenReturn(true);
        when(accountLockService.isAccountLocked(domainFreeUsername, TENANT_DOMAIN, userStoreDomain))
                .thenReturn(locked);
        when(accountDisableService.isAccountDisabled(domainFreeUsername, TENANT_DOMAIN, userStoreDomain))
                .thenReturn(disabled);
    }

    private void mockAccountDisablingEnabled(boolean enabled) {

        Property property = new Property();
        property.setValue(String.valueOf(enabled));
        frameworkUtils.when(() -> FrameworkUtils.getResidentIdpConfiguration(
                FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, TENANT_DOMAIN))
                .thenReturn(property);
    }

    private IdentityProvider getResidentIdP() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);
        return identityProvider;
    }

    private IdentityProvider getFederatedIdP() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(FEDERATED_IDP_NAME);
        return identityProvider;
    }
}
