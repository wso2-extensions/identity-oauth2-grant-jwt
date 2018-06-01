/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

public class JWTConstants {

    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "assertion";
    public static final String VALIDITY_PERIOD = "validityPeriod";
    public static final String CACHE_USED_JTI = "cacheUsed";
    public static final String PROPERTIES_FILE = "jwt.properties";
    public static final String JWKS_URI = "jwksUri";
    public static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";
    // Expiry time of the jwt token
    public static final String EXPIRY_TIME = "EXPIRY_TIME_JWT";
}