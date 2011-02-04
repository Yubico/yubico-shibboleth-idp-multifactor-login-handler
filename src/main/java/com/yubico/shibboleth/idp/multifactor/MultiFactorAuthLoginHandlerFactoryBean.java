/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * NOTE :
 * 
 * This file is Derivative Work from UsernamePasswordLoginHandlerFactoryBean.java
 * in the Shibboleth IdP distribution.
 * 
 * The Derivative Work is the result of a string replace to change
 * UsernamePassword into MultiFactor. The following copyright applies to the
 * Derivative Work :
 * 
 * Copyright 2011 Yubico AB.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @author Fredrik Thulin <fredrik@yubico.com>
 * 
 */

package com.yubico.shibboleth.idp.multifactor;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;
import com.yubico.shibboleth.idp.multifactor.MultiFactorAuthLoginHandler;

/**
 * Factory bean for {@link MultiFactorAuthLoginHandler}s.
 */
public class MultiFactorAuthLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** URL to authentication servlet. */
    private String authenticationServletURL;

    /**
     * Gets the URL to authentication servlet.
     * 
     * @return URL to authentication servlet
     */
    public String getAuthenticationServletURL() {
        return authenticationServletURL;
    }

    /**
     * Sets URL to authentication servlet.
     * 
     * @param url URL to authentication servlet
     */
    public void setAuthenticationServletURL(String url) {
        authenticationServletURL = url;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        MultiFactorAuthLoginHandler handler = new MultiFactorAuthLoginHandler(
                authenticationServletURL);

        populateHandler(handler);

        return handler;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
	public Class getObjectType() {
        return MultiFactorAuthLoginHandler.class;
    }
}