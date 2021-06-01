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
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolHandler;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class SendStarttlsAsciiAction extends StarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final StarttlsCommandType commandType;

    public SendStarttlsAsciiAction(StarttlsCommandType commandType) {
        super();
        this.commandType = commandType;
    }

    public SendStarttlsAsciiAction(Config config, StarttlsCommandType commandType) {
        super(config);
        this.commandType = commandType;
    }

    public SendStarttlsAsciiAction(String asciiText, String encoding, Config config, StarttlsCommandType commandType) {
        super(asciiText, encoding, config);
        this.commandType = commandType;
    }

    public SendStarttlsAsciiAction(String encoding, Config config, StarttlsCommandType commandType) {
        super(encoding, config);
        this.commandType = commandType;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        try {
            setAsciiText(initAsciiText(tlsContext));
            LOGGER.info(getActionInfo() + getAsciiText());
            tlsContext.getTransportHandler().sendData(getAsciiText().getBytes(getEncoding()));
            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    public StarttlsCommandType getCommandType() {
        return commandType;
    }

    public String initAsciiText(TlsContext tlsContext) {
        return getHandler().createCommand(tlsContext, getCommandType());
    }

    @Override
    public String getActionInfo() {
        return "Sending Starttls Message with type:" + getCommandType().toString();
    }
}
