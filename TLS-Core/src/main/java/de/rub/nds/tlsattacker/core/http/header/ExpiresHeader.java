/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.ExpiresHeaderPreparator;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;

public class ExpiresHeader extends HttpHeader {

    public ExpiresHeader() {}

    @Override
    public ExpiresHeaderPreparator getPreparator(HttpContext httpContext) {
        return new ExpiresHeaderPreparator(httpContext.getChooser(), this);
    }
}
