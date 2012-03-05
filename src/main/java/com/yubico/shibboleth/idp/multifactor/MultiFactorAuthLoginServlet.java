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
 * This file is Derivative Work from UsernamePasswordLoginServlet.java
 * in the Shibboleth IdP distribution.
 * 
 * The Derivative Work is 
 * 
 *  1) the result of a string replace to change UsernamePassword into
 *     MultiFactor
 *  2) adding the ability to extract multiple authentication tokens
 *     from the HTTP request (j_tokens)
 *  3) the ability to transfer multiple tokens to JAAS modules that pass
 *     an extended PasswordCallback to the MultiAuthCallbackHandler set
 *     up here. 
 * 
 * The following copyright applies to the Derivative Work :
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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordCredential;

/**
 * This Servlet authenticates a user via JAAS. The user's credential is always added to the returned {@link Subject} as
 * a {@link MultiFactorAuthCredential} within the subject's private credentials.
 */
public class MultiFactorAuthLoginServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MultiFactorAuthLoginServlet.class);
    
    /** The authentication method returned to the authentication engine. */
    private String authenticationMethod;

    /** Name of JAAS configuration used to authenticate users. */
    private String jaasConfigName = "ShibUserPassAuth";

    /** init-param which can be passed to the servlet to override the default JAAS config. */
    private final String jaasInitParam = "jaasConfigName";

    /** Login page name. */
    private String loginPage = "login.jsp";

    /** init-param which can be passed to the servlet to override the default login page. */
    private final String loginPageInitParam = "loginPage";

    /** Parameter name to indicate login failure. */
    private final String failureParam = "loginFailed";

    /** HTTP request parameter containing the user name. */
    private final String usernameAttribute = "j_username";

    /** HTTP request parameter containing the user's password. */
    private final String passwordAttribute = "j_password";

    /** HTTP request parameter containing the user's authentication tokens. */
    private final String tokenAttribute = "j_tokens";

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter(jaasInitParam) != null) {
            jaasConfigName = getInitParameter(jaasInitParam);
        }

        if (getInitParameter(loginPageInitParam) != null) {
            loginPage = getInitParameter(loginPageInitParam);
        }
        if (!loginPage.startsWith("/")) {
            loginPage = "/" + loginPage;
        }
        
        String method =
                DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = "urn:oasis:names:tc:SAML:2.0:ac:classes:Token";
        }
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
    IOException {
        String username = request.getParameter(usernameAttribute);
        /* The first factor is often a JAAS module that performs some kind of "legacy" authentication,
         * like Kerberos or LDAP. Such JAAS modules are expected to get the password via a PasswordCallback.
         */
        String password = request.getParameter(passwordAttribute);
        ArrayList<char[]> secrets = new ArrayList<char[]>();

        if (username == null || password == null) {
            redirectToLoginPage(request, response);
            return;
        }

        /* Always store the first factor (password) in the first element of secrets. */ 
        secrets.add(password.toCharArray());

        /* Now look for additional authentication factor parameters in the request */
        int i = 0;
        String t = request.getParameter(tokenAttribute + "[" + i + "]"); 
        while (t != null) {
            secrets.add(t.toCharArray());
            i++;
            t = request.getParameter(tokenAttribute + "[" + i + "]"); 
        }

        log.debug("Extracted {} authentication factors from request", secrets.size());

        try {
            authenticateUser(request, username, password, secrets);
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
        } catch (LoginException e) {
            request.setAttribute(failureParam, "true");
            request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, new AuthenticationException(e));
            redirectToLoginPage(request, response);
        }
    }

    /**
     * Sends the user to the login page.
     * 
     * @param request current request
     * @param response current response
     */
    protected void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response) {

        StringBuilder actionUrlBuilder = new StringBuilder();
        if(!"".equals(request.getContextPath())){
            actionUrlBuilder.append(request.getContextPath());
        }
        actionUrlBuilder.append(request.getServletPath());

        request.setAttribute("actionUrl", actionUrlBuilder.toString());

        try {
            request.getRequestDispatcher(loginPage).forward(request, response);
            log.debug("Redirecting to login MultiFactorAuth page {}", loginPage);
        } catch (IOException ex) {
            log.error("Unable to redirect to login page.", ex);
        } catch (ServletException ex) {
            log.error("Unable to redirect to login page.", ex);
        }
    }

    /**
     * Authenticate a username and one or more authentication factors against JAAS.
     * If authentication succeeds the name of the first principal, or the username if
     * that is empty, and the subject are placed into the request in their respective attributes.
     * 
     * @param request current authentication request
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     * 
     * @throws LoginException thrown if there is a problem authenticating the user
     */
    protected void authenticateUser(HttpServletRequest request, String username, String password, ArrayList<char[]> secrets) throws LoginException {
        try {
            log.debug("Attempting to MultiFactor-authenticate user {}", username);

            MultiAuthCallbackHandler cbh = new MultiAuthCallbackHandler(username, secrets);

            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    jaasConfigName, cbh);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);

            Subject loginSubject = jaasLoginCtx.getSubject();

            Set<Principal> principals = loginSubject.getPrincipals();
            principals.add(new UsernamePrincipal(username));
            
            log.debug("MultiFactor authentication resulted in these principals :");
            for (Principal p : principals) {
                log.debug("   {} {}", p.getClass(), p.getName());
            }

            Set<Object> publicCredentials = loginSubject.getPublicCredentials();

            Set<Object> privateCredentials = loginSubject.getPrivateCredentials();
            privateCredentials.add(new UsernamePasswordCredential(username, password));

            Subject userSubject = new Subject(false, principals, publicCredentials, privateCredentials);
            request.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        } catch (LoginException e) {
            log.debug("User authentication for " + username + " failed", e);
            throw e;
        } catch (Throwable e) {
            log.debug("User authentication for " + username + " failed", e);
            throw new LoginException("unknown authentication error");
        }
    }

    /**
     * A callback handler that provides static name and authentication tokens
     * to a JAAS login process.
     * 
     * This handler only supports {@link NameCallback} and {@link PasswordCallback}.
     */
    protected class MultiAuthCallbackHandler implements CallbackHandler {

        /** Name of the user. */
        private String uname;

        /** User's password. Kept in char[]'s to be possible to wipe from memory. */
        private ArrayList<char[]> secrets;

        /**
         * Constructor.
         * 
         * @param username The username
         * @param password The password
         */
        public MultiAuthCallbackHandler(String username, ArrayList<char[]> newSecrets) {
            uname = username;
            secrets = newSecrets;
        }

        /**
         * Handle a callback.
         * 
         * @param callbacks The list of callbacks to process.
         * 
         * @throws UnsupportedCallbackException If callbacks has a callback other than {@link NameCallback} or
         *             {@link PasswordCallback}.
         */
        public void handle(final Callback[] callbacks) throws UnsupportedCallbackException, IOException {

            if (callbacks == null || callbacks.length == 0) {
                return;
            }

            for (Callback cb : callbacks) {
                if (cb instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) cb;
                    ncb.setName(uname);
                } else if (cb instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) cb;

                    ArrayList<char []> r_secrets = this.secrets;
                    Collections.reverse(r_secrets);

                    /* Add all our secrets. Since we reversed the list, the last
                     * one to be added is the first token (j_password in HTTP request).
                     * If this instance of PasswordCallback only supports one value,
                     * it will thus get the first token. If it supports multiple values,
                     * all will be available.
                     */
                    for (char[] c : r_secrets) {
                        pcb.setPassword(c);
                    }
                }
            }
        }
    }
}