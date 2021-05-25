/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.starttls.StarttlsActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class POP3Handler implements StarttlsProtocolHandler {

    @Override
    public void handleServerGreeting(TlsContext tlsContext, String str) {

    }

    @Override
    public void handleCapabilities(TlsContext tlsContext, String str) {
        String[] parts = str.split(" |\\r?\\n"); // Split string on
        // space and new
        // Line.
        List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
        for (String s : parts) {
            ServerCapability capa = ServerCapability.getCapabilityFromString(StarttlsType.POP3, s);
            if (capa != null)
                capabilities.add(capa);
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
                    builder.append("\r\n" + capa.getServerCapability());
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
        return null;
    }

    @Override
    public Map<StarttlsCommandType, String> expectedCommandsDict() {
        Map<StarttlsCommandType, String> dict = new HashMap<>();
        dict.put(StarttlsCommandType.C_STARTTLS, "STLS");
        dict.put(StarttlsCommandType.C_CAPA, "CAPA");
        dict.put(StarttlsCommandType.C_QUIT, "QUIT");
        // dict.put(StarttlsCommandType.C_NOOP, "AUTH");
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
    public WorkflowTrace extendWorkflowTrace(AliasedConnection connection, Config config, WorkflowTrace workflowTrace) {
        workflowTrace.addTlsAction(StarttlsActionFactory.createServerGreetingAction(config, connection,
                ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(config, connection,
                ConnectionEndType.CLIENT, StarttlsCommandType.C_STARTTLS, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createIssueStarttlsCommandAction(config, connection,
                ConnectionEndType.SERVER, StarttlsCommandType.S_STARTTLS, "US-ASCII"));
        return workflowTrace;
    }
}
