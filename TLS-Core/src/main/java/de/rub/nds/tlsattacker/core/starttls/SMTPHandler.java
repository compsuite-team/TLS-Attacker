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

public class SMTPHandler implements StarttlsProtocolHandler {
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
            ServerCapability capa = ServerCapability.getCapabilityFromString(StarttlsType.SMTP, s);
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
                return "220 mail.example.com Hello from SMTP\r\n";
            case C_CAPA:
                return "EHLO mail.example.com\r\n";
            case S_CAPA:
                List<ServerCapability> capabilities = config.getDefaultServerCapabilities();
                StringBuilder builder = new StringBuilder();
                builder.append("250-mail.example.org\r\n");
                if (!capabilities.isEmpty()) {
                    for (int i = 0; i < capabilities.size() - 1; i++) {
                        builder.append("250-" + capabilities.get(i).getServerCapability() + "\r\n");
                    }
                    builder.append("250 " + capabilities.get(capabilities.size() - 1).getServerCapability() + "\r\n");
                }
                return builder.toString();
            case C_STARTTLS:
                return "STARTTLS\r\n";
            case S_STARTTLS:
                return "220 Go ahead with TLS negotiation\r\n";
            case C_NOOP:
                return "NOOP\r\n";
            case S_OK:
                return "250 OK\r\n";
            case C_QUIT:
                return "QUIT\r\n";
            case S_BYE:
                return "221 OK\r\n";
            case S_ERR:
                return "504 command not implemented\r\n";
        }
        return null;
    }

    @Override
    public Map<StarttlsCommandType, String> expectedCommandsDict() {
        Map<StarttlsCommandType, String> dict = new HashMap<>();
        dict.put(StarttlsCommandType.C_CAPA, "EHLO");
        dict.put(StarttlsCommandType.C_STARTTLS, "STARTTLS");
        dict.put(StarttlsCommandType.C_NOOP, "NOOP");
        dict.put(StarttlsCommandType.C_QUIT, "QUIT");
        return dict;
    }

    @Override
    public Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses() {
        Map<StarttlsCommandType, StarttlsCommandType> dict = new HashMap<>();
        dict.put(StarttlsCommandType.C_NOOP, StarttlsCommandType.S_OK);
        dict.put(StarttlsCommandType.C_QUIT, StarttlsCommandType.S_BYE);
        dict.put(StarttlsCommandType.C_CAPA, StarttlsCommandType.S_CAPA);
        return dict;
    }

    @Override
    public WorkflowTrace extendWorkflowTrace(AliasedConnection connection, Config config, WorkflowTrace workflowTrace) {
        workflowTrace.addTlsAction(StarttlsActionFactory.createServerGreetingAction(config, connection,
                ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(config, connection,
                ConnectionEndType.CLIENT, StarttlsCommandType.C_CAPA, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createServerCapabilitiesAction(config, connection,
                ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(config, connection,
                ConnectionEndType.CLIENT, StarttlsCommandType.C_STARTTLS, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createIssueStarttlsCommandAction(config, connection,
                ConnectionEndType.SERVER, StarttlsCommandType.S_STARTTLS, "US-ASCII"));
        return workflowTrace;
    }
}
