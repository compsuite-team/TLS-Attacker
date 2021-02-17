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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class StarttlsActionFactory {

    private StarttlsActionFactory() {

    }

    public static AsciiAction createIssueStarttlsCommandAction(Config tlsConfig, AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd, StarttlsMessageFactory.CommandType commandType, String encoding) {
        StarttlsMessageFactory factory = new StarttlsMessageFactory(tlsConfig);
        String message;
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            message = factory.createSendCommand(commandType);
            action = new SendStarttlsResponseAction(encoding, tlsConfig);
        } else {
            action = new ReceiveStarttlsResponseAction(encoding);
        }
        return action;
    }

    public static AsciiAction createStarttlsAsciiAction(Config tlsConfig, AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd, StarttlsMessageFactory.CommandType commandType, String encoding) {
        StarttlsMessageFactory factory = new StarttlsMessageFactory(tlsConfig);
        String message;
        AsciiAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            message = factory.createSendCommand(commandType);
            action = new SendAsciiAction(message, encoding);
        } else {
            action = new GenericReceiveAsciiAction(encoding);
        }
        return action;
    }

    public static AsciiAction createStarttlsCommunicationAction(Config tlsConfig, AliasedConnection connection,
            ConnectionEndType sendingConnectionEnd, StarttlsMessageFactory.CommandType commandType, String encoding) {
        StarttlsMessageFactory factory = new StarttlsMessageFactory(tlsConfig);
        AsciiAction action;
        String message;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            message = factory.createSendCommand(commandType);
            action = new SendAsciiAction(message, encoding);
        } else {
            message = factory.createExpectedCommand(commandType);
            action = new StarttlsAnswerTillAction(tlsConfig, message, encoding);
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
