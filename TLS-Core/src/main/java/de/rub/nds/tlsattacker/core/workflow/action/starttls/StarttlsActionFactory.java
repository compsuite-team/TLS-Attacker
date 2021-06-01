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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAsciiAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class StarttlsActionFactory {

    private StarttlsActionFactory() {

    }

    public static AsciiAction createIssueStarttlsCommandAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, StarttlsCommandType commandType, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendStarttlsResponseAction(encoding, tlsConfig);
        } else {
            action = new ReceiveStarttlsResponseAction(encoding);
        }
        return action;
    }

    public static AsciiAction createStarttlsAsciiAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, StarttlsCommandType commandType, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendStarttlsAsciiAction(encoding, tlsConfig, commandType);
        } else {
            action = new GenericReceiveAsciiAction(encoding);
        }
        return action;
    }

    public static AsciiAction createStarttlsCommunicationAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, StarttlsCommandType commandType, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendStarttlsAsciiAction(encoding, tlsConfig, commandType);
        } else {
            action = new StarttlsAnswerTillAction(tlsConfig, commandType, encoding);
        }
        return action;
    }

    public static AsciiAction createServerCapabilitiesAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd)
            action = new SendServerCapabilitiesAction(encoding, tlsConfig);
        else
            action = new ReceiveServerCapabilitiesAction(encoding, tlsConfig);
        return action;
    }

    public static AsciiAction createServerGreetingAction(Config tlsConfig, AliasedConnection connection,
        ConnectionEndType sendingConnectionEnd, String encoding) {
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd)
            action = new SendServerGreetingAction(encoding, tlsConfig);
        else
            action = new ReceiveServerGreetingAction(encoding, tlsConfig);
        return action;
    }
}
