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
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendServerCapabilitiesAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendServerCapabilitiesAction() {
        super(StarttlsCommandType.S_CAPA);
    }

    public SendServerCapabilitiesAction(Config config) {
        super(config, StarttlsCommandType.S_CAPA);
    }

    public SendServerCapabilitiesAction(String encoding, Config config) {
        super(encoding, config, StarttlsCommandType.S_CAPA);
    }

    @Override
    public String getActionInfo() {
        return "Sending Server Capabilities: ";
    }
}
