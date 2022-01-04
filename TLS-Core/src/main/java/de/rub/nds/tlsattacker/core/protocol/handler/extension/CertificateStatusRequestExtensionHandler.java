/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import static de.rub.nds.tlsattacker.transport.ConnectionEndType.CLIENT;

public class CertificateStatusRequestExtensionHandler
    extends ExtensionHandler<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateStatusRequestExtensionMessage message) {
        if (context.getTalkingConnectionEndType() == CLIENT) {
            context.setCertificateStatusRequestExtensionRequestType(CertificateStatusRequestType
                .getCertificateStatusRequestType(message.getCertificateStatusRequestType().getValue()));
            LOGGER.debug("Adjusted the Certificate Status Request Type in the TLSContext to "
                + context.getCertificateStatusRequestExtensionRequestType());
            context.setCertificateStatusRequestExtensionRequestExtension(message.getRequestExtension().getValue());
            LOGGER.debug("Adjusted the Certificate Status Request Request Extension to "
                + bytesToHexString(context.getCertificateStatusRequestExtensionRequestExtension()));
            context.setCertificateStatusRequestExtensionResponderIDList(message.getResponderIDList().getValue());
            LOGGER.debug("Adjusted the Certificate Status Request Responder ID List to "
                + bytesToHexString(context.getCertificateStatusRequestExtensionResponderIDList()));
        }
    }

}
