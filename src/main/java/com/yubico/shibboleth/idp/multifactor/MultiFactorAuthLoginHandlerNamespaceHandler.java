/*
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

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class MultiFactorAuthLoginHandlerNamespaceHandler extends BaseSpringNamespaceHandler {
    public static final String NAMESPACE = "http://www.yubico.com/2011/shibboleth/idp";

    public void init() {
        registerBeanDefinitionParser(MultiFactorAuthLoginHandlerBeanDefinitionParser.SCHEMA_TYPE,
				     new MultiFactorAuthLoginHandlerBeanDefinitionParser());
    }
}
