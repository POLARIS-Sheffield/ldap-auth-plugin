/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnatx.plugins.auth.ldap.provider;

import static org.nrg.xdat.services.XdatUserAuthService.LDAP;

import com.google.common.collect.ImmutableList;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.provider.XnatMulticonfigAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * This class represents both an individual LDAP provider and, in the case where multiple LDAP configurations are provided
 * for a single deployment, an aggregator of LDAP providers. This differs from earlier releases of XNAT where multiple LDAP
 * configurations were represented as multiple provider instances.
 */
@Component
@Slf4j
public class XnatMulticonfigLdapAuthenticationProvider implements XnatMulticonfigAuthenticationProvider {
    @Autowired
    public XnatMulticonfigLdapAuthenticationProvider(final AuthenticationProviderConfigurationLocator locator, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        this(locator.getProviderDefinitionsByAuthMethod(LDAP), userAuthService, preferences);
    }

    public XnatMulticonfigLdapAuthenticationProvider(final Map<String, ProviderAttributes> definitions, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        if (!CollectionUtils.isEmpty(definitions)) {
            new LinkedList<>(definitions.keySet()).stream().map(definitions::get).forEach(attributes -> {
                final String providerId = attributes.getProviderId();
                _providerAttributes.put(providerId, attributes);
                _providers.put(providerId, new XnatLdapAuthenticationProvider(attributes, userAuthService, preferences));
            });
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getProviderIds() {
        return ImmutableList.copyOf(_providerAttributes.keySet());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<XnatAuthenticationProvider> getProviders() {
        return new ArrayList<>(_providers.values());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public XnatAuthenticationProvider getProvider(final String providerId) {
        return _providers.get(providerId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null ? provider.getName() : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVisible(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null && provider.isVisible();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setVisible(final String providerId, final boolean visible) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        if (provider != null) {
            provider.setVisible(visible);
            _providerAttributes.get(providerId).setVisible(visible);
        }
    }

    @Override
    public String toString() {
        return _providers.values().stream()
                         .map(XnatLdapAuthenticationProvider::getName)
                         .collect(Collectors.joining(", "));
    }

    private final Map<String, ProviderAttributes>             _providerAttributes = new HashMap<>();
    private final Map<String, XnatLdapAuthenticationProvider> _providers          = new HashMap<>();
}
