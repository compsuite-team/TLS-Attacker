/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.exceptions.StarttlsCommandTypeNotImplementedException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

import java.util.List;
import java.util.Map;

public class FTPHandler extends StarttlsProtocolHandler {
    @Override
    public void handleServerGreeting(TlsContext tlsContext, String str) {

    }

    @Override
    public void handleCapabilities(TlsContext tlsContext, String str) {

    }

    @Override
    public String createCommand(TlsContext tlsContext, StarttlsCommandType commandType) {
        switch (commandType) {
            case S_CONNECTED:
                return "211-Extensions supported\r\nAUTH TLS\r\n211 End\r\n";
            case C_STARTTLS:
                return "AUTH TLS\r\n";
            case S_STARTTLS:
                return "234 AUTH command ok. Initializing TLS Connection.\r\n";
        }
        throw new StarttlsCommandTypeNotImplementedException(
            "CommandType \"" + commandType + "\" not implemented for FTP.");
    }

    @Override
    public Map<StarttlsCommandType, String> expectedCommandsDict() {
        return null;
    }

    @Override
    public Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses() {
        return null;
    }

    @Override
    public String getNegotiationString() {
        return "234";
    }

    @Override
    public List<ServerCapability> getImplementedCapabilities() {
        return null;
    }
}
