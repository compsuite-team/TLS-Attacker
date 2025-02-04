/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.HostHeaderPreparator;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;

public class HostHeader extends HttpHeader {

    public HostHeader() {}

    @Override
    public HostHeaderPreparator getPreparator(HttpContext httpContext) {
        return new HostHeaderPreparator(httpContext.getChooser(), this);
    }
}
