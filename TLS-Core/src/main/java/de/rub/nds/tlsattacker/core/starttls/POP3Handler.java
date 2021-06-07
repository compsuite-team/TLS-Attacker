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
import de.rub.nds.tlsattacker.core.workflow.action.starttls.StarttlsActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class POP3Handler extends StarttlsProtocolHandler {

    @Override
    public void handleServerGreeting(TlsContext tlsContext, String str) {

    }

    @Override
    public void handleCapabilities(TlsContext tlsContext, String str) {
        // Split string on space and new line
        String[] parts = str.split(" |\\r?\\n");
        List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
        for (String s : parts) {
            ServerCapability capa = getCapabilityFromString(s);
            if (capa != null)
                capabilities.add(capa);
            else
                capabilities.add(new ServerCapability(s));
        }
        tlsContext.setServerCapabilities(capabilities);
    }

    @Override
    public String createCommand(TlsContext tlsContext, StarttlsCommandType commandType) {
        Config config = tlsContext.getConfig();
        switch (commandType) {
            case S_CONNECTED:
                return "+OK Bonjour from POP3\r\n";
            case C_CAPA:
                return "CAPA\r\n";
            case S_CAPA:
                StringBuilder builder = new StringBuilder();
                builder.append("+OK");
                for (ServerCapability capa : config.getDefaultServerCapabilities()) {
                    builder.append("\r\n" + capa.getName());
                }
                builder.append("\r\n.\r\n");
                return builder.toString();
            case C_STARTTLS:
                return "STLS\r\n";
            case S_STARTTLS:
                return "+OK Begin TLS negotiation\r\n";
            case C_QUIT:
                return "QUIT\r\n";
            case S_OK:
            case S_BYE:
                return "+ OK\r\n";
            case S_ERR:
                return "-ERR\r\n";
        }
        throw new StarttlsCommandTypeNotImplementedException("CommandType \"" + commandType + "\" not implemented.");
    }

    @Override
    public Map<StarttlsCommandType, String> expectedCommandsDict() {
        Map<StarttlsCommandType, String> dict = new HashMap<>();
        dict.put(StarttlsCommandType.C_STARTTLS, "STLS");
        dict.put(StarttlsCommandType.C_CAPA, "CAPA");
        dict.put(StarttlsCommandType.C_QUIT, "QUIT");
        return dict;
    }

    @Override
    public Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses() {
        Map<StarttlsCommandType, StarttlsCommandType> dict = new HashMap<StarttlsCommandType, StarttlsCommandType>();
        dict.put(StarttlsCommandType.C_CAPA, StarttlsCommandType.S_CAPA);
        dict.put(StarttlsCommandType.C_QUIT, StarttlsCommandType.S_BYE);
        dict.put(StarttlsCommandType.C_NOOP, StarttlsCommandType.S_OK);
        return dict;
    }

    @Override
    public boolean offersPlainLogin(String serverCapability) {
        ServerCapability capability = getCapabilityFromString(serverCapability);
        if (capability != null)
            return capability.isPlain();
        else if (serverCapability.startsWith("SASL") || serverCapability.startsWith("AUTH")) {
            if (serverCapability.contains("PLAIN") || serverCapability.contains("LOGIN"))
                return true;
        }
        return false;
    }

    @Override
    public String getNegotiationString() {
        return "+OK";
    }

    @Override
    public List<ServerCapability> getImplementedCapabilities() {
        List<ServerCapability> list = new LinkedList<>();
        list.add(new ServerCapability("USER", true, false, false));
        list.add(new ServerCapability("SASL PLAIN LOGIN", true, false, false));
        list.add(new ServerCapability("CAPA"));
        list.add(new ServerCapability("STLS", false, false, true));
        list.add(new ServerCapability("UIDL"));
        list.add(new ServerCapability("PIPELINING"));
        return list;
    }
}
