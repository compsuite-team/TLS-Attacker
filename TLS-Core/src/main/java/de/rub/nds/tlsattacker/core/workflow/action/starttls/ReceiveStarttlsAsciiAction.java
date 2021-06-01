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
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolHandler;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public abstract class ReceiveStarttlsAsciiAction extends StarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReceiveStarttlsAsciiAction() {
        super();
    }

    public ReceiveStarttlsAsciiAction(Config config) {
        super(config);
    }

    public ReceiveStarttlsAsciiAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding, config);
    }

    public ReceiveStarttlsAsciiAction(String encoding, Config config) {
        super(encoding, config);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted())
            throw new WorkflowExecutionException("Action already executed!");

        try {
            LOGGER.info(getActionInfo());
            byte[] fetchData = tlsContext.getTransportHandler().fetchData();
            String receivedText = new String(fetchData, getEncoding());
            setAsciiText(receivedText);
            LOGGER.info("Received: " + getAsciiText());
            setAsciiText(getAsciiText());

            handleText(tlsContext);

            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(false);
        }
    }

    public abstract void handleText(TlsContext tlsContext);
}
