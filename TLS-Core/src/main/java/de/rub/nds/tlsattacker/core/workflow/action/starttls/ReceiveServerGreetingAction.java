/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class ReceiveServerGreetingAction extends ReceiveStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReceiveServerGreetingAction() {
        super();
    }

    public ReceiveServerGreetingAction(Config config) {
        super(config);
    }

    public ReceiveServerGreetingAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding, config);
    }

    public ReceiveServerGreetingAction(String encoding, Config config) {
        super(encoding, config);
    }

    @Override
    public void handleText(TlsContext tlsContext) {
        getHandler().handleServerGreeting(tlsContext, getAsciiText());
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
        return "Receiving Server Greeting...";
    }

}
