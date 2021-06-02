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

public class SMTPHandler extends StarttlsProtocolHandler {
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
                return "220 mail.example.com Hello from SMTP\r\n";
            case C_CAPA:
                return "EHLO mail.example.com\r\n";
            case S_CAPA:
                List<ServerCapability> capabilities = config.getDefaultServerCapabilities();
                StringBuilder builder = new StringBuilder();
                builder.append("250-mail.example.org\r\n");
                if (!capabilities.isEmpty()) {
                    for (int i = 0; i < capabilities.size() - 1; i++) {
                        builder.append("250-" + capabilities.get(i).getName() + "\r\n");
                    }
                    builder.append("250 " + capabilities.get(capabilities.size() - 1).getName() + "\r\n");
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
        throw new StarttlsCommandTypeNotImplementedException("CommandType \"" + commandType + "\" not implemented.");
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
        workflowTrace.addTlsAction(
            StarttlsActionFactory.createServerGreetingAction(config, connection, ConnectionEndType.SERVER, "US-ASCII"));
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

    @Override
    public boolean offersPlainLogin(String serverCapability) {
        ServerCapability capability = getCapabilityFromString(serverCapability);
        if (capability != null)
            return capability.isPlain();
        else if (serverCapability.startsWith("250-AUTH")) {
            if (serverCapability.contains("PLAIN") || serverCapability.contains("LOGIN"))
                return true;
        }
        return false;
    }

    @Override
    public String getNegotiationString() {
        return "220";
    }

    @Override
    public List<ServerCapability> getImplementedCapabilities() {
        List<ServerCapability> list = new LinkedList<>();
        list.add(new de.rub.nds.tlsattacker.core.starttls.ServerCapability("AUTH=PLAIN", true, false, false));
        list.add(new de.rub.nds.tlsattacker.core.starttls.ServerCapability("AUTH=LOGIN", true, false, false));
        list.add(new de.rub.nds.tlsattacker.core.starttls.ServerCapability("8BITMIME"));
        list.add(new de.rub.nds.tlsattacker.core.starttls.ServerCapability("STARTTLS", false, false, true));
        return list;
    }
}
