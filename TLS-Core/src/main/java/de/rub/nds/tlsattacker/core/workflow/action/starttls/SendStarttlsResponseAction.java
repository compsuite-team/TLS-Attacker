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
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Till Budde - tbudde2@mail.uni-paderborn.de
 *
 *         class does not extend any functionalities. Is used to recognize the Server's response to the STARTTLS -
 *         command. Is used in ConnectivityChecker to determine if both parties agreed to execute TLS (SpeakStarttls)
 */
public class SendStarttlsResponseAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendStarttlsResponseAction(String encoding, Config config) {
        super(encoding, config, StarttlsCommandType.S_STARTTLS);
    }

    public SendStarttlsResponseAction(Config config) {
        super(config, StarttlsCommandType.S_STARTTLS);
    }

    public SendStarttlsResponseAction() {
        super(StarttlsCommandType.S_STARTTLS);
    }

    @Override
    public String getActionInfo() {
        return "Sending Starttls Command: ";
    }

}
