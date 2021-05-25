/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class ReceiveServerCapabilitiesAction extends ReceiveStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReceiveServerCapabilitiesAction() {
        super();
    }

    public ReceiveServerCapabilitiesAction(Config config) {
        super(config);
    }

    public ReceiveServerCapabilitiesAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding, config);
    }

    public ReceiveServerCapabilitiesAction(String encoding, Config config) {
        super(encoding, config);
    }

    @Override
    public void handleText(TlsContext tlsContext) {
        getHandler().handleCapabilities(tlsContext, getAsciiText());
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public String getActionInfo() {
        return "Receiving Server Capabilities...";
    }
}
