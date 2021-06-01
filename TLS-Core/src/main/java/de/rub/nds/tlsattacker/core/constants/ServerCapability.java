/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public enum ServerCapability {
    IMAP_CAPABILITY("CAPABILITY"),
    IMAP_IMAP4rev1("IMAP4REV1"),
    IMAP_AUTHPLAIN("AUTH=PLAIN"),
    IMAP_AUTHLOGIN("AUTH=LOGIN"),
    IMAP_LOGINDISABLED("LOGINDISABLED"),
    IMAP_STARTTLS("STARTTLS"),

    POP3_USERPLAIN("USER"),
    POP3_SASLPLAINLOGIN("SASL PLAIN LOGIN"),
    POP3_CAPA("CAPA"),
    POP3_UIDL("UIDL"),
    POP3_PIPELINING("PIPELINING"),
    POP3_STLS("STLS"),

    SMTP_AUTHPLAIN("AUTH=PLAIN"),
    SMTP_AUTHLOGIN("AUTH=LOGIN"),
    SMTP_STARTTLS("STARTTLS"),
    SMTP_8BITMIME("8BITMIME");

    private final String serverCapability;

    ServerCapability(String serverCapability) {
        this.serverCapability = serverCapability;
    }

    public String getServerCapability() {
        return serverCapability;
    }

    public static ServerCapability getCapabilityFromString(StarttlsType type, String str) {
        String comparison = str;
        for (ServerCapability capability : getImplemented(type)) {
            if (type == StarttlsType.SMTP && comparison.startsWith("250-"))
                comparison = comparison.substring(4);
            // TODO: Comparison in UpperCase|LowerCase?
            if (capability.getServerCapability().equalsIgnoreCase(comparison))
                return capability;
        }
        return null;
    }

    public static List<ServerCapability> getImplemented(StarttlsType type) {
        List<ServerCapability> list = new LinkedList<ServerCapability>();
        switch (type) {
            case IMAP:
                list.add(IMAP_CAPABILITY);
                list.add(IMAP_IMAP4rev1);
                list.add(IMAP_AUTHPLAIN);
                list.add(IMAP_AUTHLOGIN);
                list.add(IMAP_LOGINDISABLED);
                list.add(IMAP_STARTTLS);
                break;
            case POP3:
                list.add(POP3_USERPLAIN);
                list.add(POP3_SASLPLAINLOGIN);
                list.add(POP3_CAPA);
                list.add(POP3_UIDL);
                list.add(POP3_PIPELINING);
                list.add(POP3_STLS);
                break;
            case SMTP:
                list.add(SMTP_AUTHPLAIN);
                list.add(SMTP_AUTHLOGIN);
                list.add(SMTP_STARTTLS);
                list.add(SMTP_8BITMIME);
                break;
        }
        return list;
    }

    public static List<ServerCapability> getPlainLogin() {
        List<ServerCapability> list = new LinkedList<ServerCapability>();
        list.add(IMAP_AUTHPLAIN);
        list.add(IMAP_AUTHLOGIN);
        list.add(POP3_USERPLAIN);
        list.add(POP3_SASLPLAINLOGIN);
        list.add(SMTP_AUTHPLAIN);
        list.add(SMTP_AUTHLOGIN);
        return list;
    }

    public static boolean isLoginDisabled(ServerCapability capa) {
        return capa == IMAP_LOGINDISABLED;
    }

    public static boolean isStarttlsCommand(ServerCapability capa) {
        return capa == SMTP_STARTTLS || capa == IMAP_STARTTLS || capa == POP3_STLS;
    }

    public static boolean isPlainLogin(ServerCapability capa) {
        return getPlainLogin().contains(capa);
    }

    public static boolean offersPlainLogin(StarttlsType type, String serverCapability) {
        List<ServerCapability> plainLogins = getPlainLogin();
        ServerCapability capability = getCapabilityFromString(type, serverCapability);
        if (capability != null) {
            if (plainLogins.contains(capability))
                return true;
        } else if ((type == StarttlsType.POP3
            && (serverCapability.startsWith("SASL") || serverCapability.startsWith("AUTH")))
            || (type == StarttlsType.SMTP && serverCapability.startsWith("250-AUTH"))) {
            if (serverCapability.contains("PLAIN") || serverCapability.contains("LOGIN"))
                return true;
        }
        return false;
    }

}
