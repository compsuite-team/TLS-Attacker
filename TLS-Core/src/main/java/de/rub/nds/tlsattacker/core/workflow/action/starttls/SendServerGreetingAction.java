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
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.stream.Collectors;

public class SendServerGreetingAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendServerGreetingAction() {
        super(StarttlsCommandType.S_CONNECTED);
    }

    public SendServerGreetingAction(Config config) {
        super(config, StarttlsCommandType.S_CONNECTED);
    }

    public SendServerGreetingAction(String encoding, Config config) {
        super(encoding, config, StarttlsCommandType.S_CONNECTED);
    }

    @Override
    public String getActionInfo() {
        return "Sending Server Greeting: ";
    }
}
