/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SendServerCapabilitiesAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendServerCapabilitiesAction() {
        super();
    }

    public SendServerCapabilitiesAction(Config config) {
        super(config);
    }

    public SendServerCapabilitiesAction(String encoding, Config config) {
        super(encoding, config);
    }

    @Override
    public String initAsciiText(TlsContext tlsContext) {
        Chooser chooser = tlsContext.getChooser();
        StarttlsMessageFactory factory = new StarttlsMessageFactory(getConfig());
        return factory.createCommand(StarttlsMessageFactory.CommandType.S_CAPA, tlsContext.getRecentIMAPTag());
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
        return "Sending Server Capabilities: ";
    }
}
