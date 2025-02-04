/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;

public class CertificateTypeExtensionHandler
        extends ExtensionHandler<CertificateTypeExtensionMessage> {

    public CertificateTypeExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateTypeExtensionMessage message) {
        tlsContext.setCertificateTypeDesiredTypes(
                CertificateType.getCertificateTypesAsList(
                        message.getCertificateTypes().getValue()));
    }
}
