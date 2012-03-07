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
 * This file is Derivative Work from UsernamePasswordLoginHandlerBeanDefinitionParser.java
 * in the Shibboleth IdP distribution.
 * 
 * The Derivative Work is the result of a couple of string replaces to change
 * UsernamePassword into MultiFactor and similar. The following copyright applies to the
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

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;

/**
 * Spring bean definition parser for username/password authentication handlers.
 */
public class MultiFactorAuthLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(MultiFactorAuthLoginHandlerNamespaceHandler.NAMESPACE, "MultiFactorAuth");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MultiFactorAuthLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
	protected Class getBeanClass(Element element) {
        return MultiFactorAuthLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "authenticationServletURL")) {
            builder.addPropertyValue("authenticationServletURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,
                    "authenticationServletURL")));
        } else {
            builder.addPropertyValue("authenticationServletURL", "/Authn/MultiFactor");
        }

        String jaasConfigurationURL = DatatypeHelper.safeTrim(config.getAttributeNS(null, "jaasConfigurationLocation"));
        log.debug("Setting JAAS configuration file to: {}", jaasConfigurationURL);
        System.setProperty("java.security.auth.login.config", jaasConfigurationURL);
    }
}