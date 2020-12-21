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

/**
 * @author Till Budde - tbudde2@mail.uni-paderborn.de
 *
 *         class does not extend any functionalities. Is used to recognize the
 *         Server's response to the STARTTLS - command. Is used in
 *         ConnectivityChecker to determine if both parties agreed to execute
 *         TLS (SpeakStarttls)
 */
public class ReceiveStarttlsCommandAction extends GenericReceiveAsciiAction {

    public ReceiveStarttlsCommandAction(String encoding) {
        super(encoding);
    }

}
