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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Till Budde - tbudde2@mail.uni-paderborn.de
 *
 *         class does not extend any functionalities. Is used to recognize the
 *         Server's response to the STARTTLS - command. Is used in
 *         ConnectivityChecker to determine if both parties agreed to execute
 *         TLS (SpeakStarttls)
 */
public class SendStarttlsResponseAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendStarttlsResponseAction(String encoding, Config config) {
        super(encoding, config);
    }

    public SendStarttlsResponseAction(Config config) {
        super(config);
    }

    private SendStarttlsResponseAction() {
    }

    @Override
    public String initAsciiText(TlsContext tlsContext) {
        StarttlsMessageFactory factory = new StarttlsMessageFactory(getConfig());
        return factory.createCommand(StarttlsMessageFactory.CommandType.S_STARTTLS, tlsContext.getRecentIMAPTag());
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public String getActionInfo() {
        return "Sending Starttls Command: ";
    }

}
