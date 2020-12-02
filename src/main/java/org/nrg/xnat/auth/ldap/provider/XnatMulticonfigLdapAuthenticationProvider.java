/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnat.auth.ldap.provider;

import com.google.common.collect.ImmutableList;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.tokens.XnatLdapUsernamePasswordAuthenticationToken;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.provider.XnatMulticonfigAuthenticationProvider;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

import static org.nrg.xdat.services.XdatUserAuthService.LDAP;

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
        if (definitions != null) {
            final List<ProviderAttributes> configurations = getOrderedConfigurations(definitions);
            for (final ProviderAttributes attributes : configurations) {
                final String providerId = attributes.getProviderId();
                _providerAttributes.put(providerId, attributes);
                _providers.put(providerId, new XnatLdapAuthenticationProvider(attributes, userAuthService, preferences));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        String providerId = null;
        if (authentication instanceof XnatLdapUsernamePasswordAuthenticationToken) {
            providerId = ((XnatLdapUsernamePasswordAuthenticationToken) authentication).getProviderId();
        }
        if (providerId != null) {
            return authenticateByProviderId(providerId, authentication);
        } else {
            for (final String pid : _providers.keySet()) {
                Authentication processed = authenticateByProviderId(pid, authentication);
                if (processed != null) {
                    return processed;
                }
            }

            // We didn't authenticate so return null.
            return null;
        }
    }

    private Authentication authenticateByProviderId(String providerId, Authentication authentication) {
        final XnatLdapAuthenticationProvider provider = _providers.get(providerId);
        final Authentication processed = provider.authenticate(authentication);
        if (processed != null && processed.isAuthenticated()) {
            return processed;
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getProviderIds() {
        return ImmutableList.copyOf(_providerAttributes.keySet());
    }

    @Override
    public List<XnatAuthenticationProvider> getProviders() {
        return new ArrayList<XnatAuthenticationProvider>(_providers.values());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getProviderId() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAuthMethod() {
        return XdatUserAuthService.LDAP;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return _providers.values().stream().map(XnatLdapAuthenticationProvider::getName)
                .collect(Collectors.joining(", "));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVisible() {
        return _providers.values().stream().anyMatch(XnatLdapAuthenticationProvider::isVisible);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setVisible(boolean visible) {
        for (XnatLdapAuthenticationProvider provider : _providers.values()) {
            provider.setVisible(visible);
        }
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
    public boolean isAutoEnabled() {
        return _autoEnabled;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAutoEnabled(final boolean autoEnabled) {
        _autoEnabled = autoEnabled;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAutoVerified() {
        return _autoVerified;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAutoVerified(final boolean autoVerified) {
        _autoVerified = autoVerified;
    }

    @Override
    public int getOrder() {
        return getOrder(null);
    }

    @Override
    public void setOrder(int order) {
        setOrder(null, order);
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

    /**
     * @deprecated Ordering of authentication providers is set through the {@link SiteConfigPreferences#getEnabledProviders()} property.
     */
    @Deprecated
    @Override
    public int getOrder(final String providerId) {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
        return 0;
    }

    /**
     * @deprecated Ordering of authentication providers is set through the {@link SiteConfigPreferences#getEnabledProviders()} property.
     */
    @Deprecated
    @Override
    public void setOrder(final String providerId, final int order) {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public XnatAuthenticationToken createToken(final String username, final String password) {
        throw new RuntimeException("You must specify an LDAP provider to authenticate");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return XnatLdapUsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(final Authentication authentication) {
        return supports(authentication.getClass()) &&
               authentication instanceof XnatLdapUsernamePasswordAuthenticationToken &&
               _providers.containsKey(((XnatLdapUsernamePasswordAuthenticationToken) authentication).getProviderId());
    }

    @Override
    public String toString() {
        return getName();
    }

    @Nonnull
    private static List<ProviderAttributes> getOrderedConfigurations(final Map<String, ProviderAttributes> definitions) {
        if (definitions == null || definitions.isEmpty()) {
            return Collections.emptyList();
        }
        final List<ProviderAttributes> configurations = new ArrayList<>();
        for (final String key : new LinkedList<>(definitions.keySet())) {
            configurations.add(definitions.get(key));
        }
        return configurations;
    }

    private final Map<String, ProviderAttributes>             _providerAttributes = new HashMap<>();
    private final Map<String, XnatLdapAuthenticationProvider> _providers          = new HashMap<>();

    private boolean _autoEnabled;
    private boolean _autoVerified;
}
