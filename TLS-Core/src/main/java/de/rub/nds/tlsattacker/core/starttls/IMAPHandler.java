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
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.StarttlsCommandTypeNotImplementedException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.starttls.StarttlsActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import java.util.*;
import java.util.stream.Collectors;

public class IMAPHandler implements StarttlsProtocolHandler {

    @Override
    public void handleServerGreeting(TlsContext tlsContext, String str) {
        String[] parts = str.split(" ");
        if (parts.length >= 2) {
            if ("PREAUTH".equals(parts[1]))
                tlsContext.setIsPreauth(true);
        }
        if (parts.length >= 2 && parts[2] != null && parts[2].startsWith("[")) {
            tlsContext.setCapaInGreeting(true);
            List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
            for (int i = 2; i < parts.length; i++) {
                String capability = parts[i];
                if (capability.startsWith("["))
                    capability = capability.substring(1);
                if (capability.endsWith("]"))
                    capability = capability.substring(0, capability.length() - 1);
                ServerCapability capa = ServerCapability.getCapabilityFromString(StarttlsType.IMAP, capability);
                if (capa != null)
                    capabilities.add(capa);
            }
            tlsContext.setServerCapabilities(capabilities);
        }
    }

    @Override
    public void handleCapabilities(TlsContext tlsContext, String str) {
        String[] parts = str.split(" |\\r?\\n"); // Split string on
        // space and new
        // Line.
        List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
        for (String s : parts) {
            ServerCapability capa = ServerCapability.getCapabilityFromString(StarttlsType.IMAP, s);
            if (capa != null)
                capabilities.add(capa);
        }
        tlsContext.setServerCapabilities(capabilities);
    }

    @Override
    public String createCommand(TlsContext tlsContext, StarttlsCommandType commandType) {
        String IMAPTag = tlsContext.getRecentIMAPTag();
        Config config = tlsContext.getConfig();
        if (!"".equals(IMAPTag))
            IMAPTag = IMAPTag + " ";
        StringBuilder builder = new StringBuilder();
        for (ServerCapability capa : config.getDefaultServerCapabilities()) {
            if (!(commandType == StarttlsCommandType.S_CAPA && capa == ServerCapability.IMAP_CAPABILITY))
                builder.append(" " + capa.getServerCapability());
        }
        switch (commandType) {
            case S_CONNECTED:
                return "* " + (config.getIMAPPreAuth() ? "PREAUTH" : "OK")
                    + (config.getIMAPCapaInGreeting() ? " [" + builder.toString() + "]" : "") + " Service Ready\r\n";
            case C_CAPA:
                return "A1 CAPABILITY\r\n";
            case S_CAPA:
                return "* CAPABILITY" + builder.toString() + "\r\n" + IMAPTag + "OK caps done\r\n";
            case C_STARTTLS:
                return "A2 STARTTLS\r\n";
            case S_STARTTLS:
                return IMAPTag + "OK Begin TLS negotiation\r\n";
            case S_OK:
                return IMAPTag + "OK done\r\n";
            case C_NOOP:
                return "A3 NOOP\r\n";
            case C_QUIT:
                return "A4 LOGOUT\r\n";
            case S_BYE:
                return "* BYE\r\n" + IMAPTag + "OK done\r\n";
            case S_ERR:
                return "* BAD command not implemented\r\n";
        }
        throw new StarttlsCommandTypeNotImplementedException("CommandType \"" + commandType + "\" not implemented.");
    }

    @Override
    public Map<StarttlsCommandType, String> expectedCommandsDict() {
        Map<StarttlsCommandType, String> dict = new HashMap<>();
        dict.put(StarttlsCommandType.C_CAPA, "CAPABILITY");
        dict.put(StarttlsCommandType.C_STARTTLS, "STARTTLS");
        dict.put(StarttlsCommandType.C_NOOP, "NOOP");
        dict.put(StarttlsCommandType.C_QUIT, "LOGOUT");
        return dict;
    }

    @Override
    public Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses() {
        Map<StarttlsCommandType, StarttlsCommandType> dict = new HashMap<StarttlsCommandType, StarttlsCommandType>();
        dict.put(StarttlsCommandType.C_NOOP, StarttlsCommandType.S_OK);
        dict.put(StarttlsCommandType.C_CAPA, StarttlsCommandType.S_CAPA);
        dict.put(StarttlsCommandType.C_QUIT, StarttlsCommandType.S_BYE);
        return dict;
    }

    @Override
    public WorkflowTrace extendWorkflowTrace(AliasedConnection connection, Config config, WorkflowTrace workflowTrace) {
        workflowTrace.addTlsAction(
            StarttlsActionFactory.createServerGreetingAction(config, connection, ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(config, connection,
            ConnectionEndType.CLIENT, StarttlsCommandType.C_STARTTLS, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createIssueStarttlsCommandAction(config, connection,
            ConnectionEndType.SERVER, StarttlsCommandType.S_STARTTLS, "US-ASCII"));
        return workflowTrace;
    }

    @Override
    public String getNegotiationString() {
        return "negotiation";
    }
}
