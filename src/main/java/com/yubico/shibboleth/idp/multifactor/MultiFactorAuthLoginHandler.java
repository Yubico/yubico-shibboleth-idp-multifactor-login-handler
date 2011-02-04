/*
 * Copyright 2006 University Corporation for Advanced Internet Development, Inc.
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
 * This file is Derivative Work from UsernamePasswordLoginHandler.java
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

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Authenticate a username and password against a JAAS source.
 * 
 * This login handler creates a {@link javax.security.auth.Subject} and binds it to the request as described in the
 * {@link edu.internet2.middleware.shibboleth.idp.authn.LoginHandler} documentation. If the JAAS module does not create
 * a principal for the user a {@link edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal} is created, using
 * the entered username. If the <code>storeCredentialsInSubject</code> init parameter of the authentication servlet is
 * set to true a {@link UsernamePasswordCredential} is created, based on the entered username and password, and stored
 * in the Subject's private credentials.
 */
public class MultiFactorAuthLoginHandler extends AbstractLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MultiFactorAuthLoginHandler.class);

    /** The context-relative path of the servlet used to perform authentication. */
    private String authenticationServletPath;

    /**
     * Constructor.
     * 
     * @param servletPath context-relative path to the authentication servlet, may start with "/"
     */
    public MultiFactorAuthLoginHandler(String servletPath) {
        super();
        setSupportsPassive(false);
        setSupportsForceAuthentication(true);
        authenticationServletPath = servletPath;
    }

    /** {@inheritDoc} */
    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {
        // forward control to the servlet.
        try {
            String authnServletUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, authenticationServletPath)
                    .buildURL();
            log.debug("Redirecting to {}", authnServletUrl);
            httpResponse.sendRedirect(authnServletUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }

    }
}