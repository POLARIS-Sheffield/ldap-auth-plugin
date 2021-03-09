/*
 * web: XnatLdapUsernamePasswordAuthenticationToken
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnatx.plugins.auth.ldap.tokens;

import org.nrg.xnat.security.tokens.AbstractXnatAuthenticationToken;

public class XnatLdapUsernamePasswordAuthenticationToken extends AbstractXnatAuthenticationToken {
    public XnatLdapUsernamePasswordAuthenticationToken(final Object principal, final Object credentials, final String providerId) {
        super(providerId, principal, credentials);
        _string = getPrincipal() + ":" + getProviderId();
    }

    public String toString() {
        return _string;
    }

    private final String _string;
}
