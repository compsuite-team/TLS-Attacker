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
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public abstract class SendStarttlsAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    public SendStarttlsAsciiAction() {
        super();
        config = null;
    }

    public SendStarttlsAsciiAction(Config config) {
        super();
        this.config = config;
    }

    public SendStarttlsAsciiAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding);
        this.config = config;
    }

    public SendStarttlsAsciiAction(String encoding, Config config) {
        super(encoding);
        this.config = config;
    }

    /**
     *
     * @return the Starttls Type
     */
    public StarttlsType getType() {
        if (config == null)
            return StarttlsType.NONE;
        return config.getStarttlsType();
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

    public abstract String initAsciiText(TlsContext tlsContext);

    public abstract String getActionInfo();
}
