/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.LinkedList;
import java.util.List;

public enum ServerCapability {
    IMAP_IMAP4rev1("IMAP4rev1"),
    IMAP_AUTHPLAIN("AUTH=PLAIN"),
    IMAP_AUTHLOGIN("AUTH=LOGIN"),
    IMAP_AUTHDISABLED("AUTH=DISABLED"),
    IMAP_STARTTLS("STARTTLS"),

    POP3_USERPLAIN("USER=PLAIN"),
    POP3_USERLOGIN("USER=LOGIN"),
    POP3_SASLPLAIN("SASL=PLAIN"),
    POP3_SASLLOGIN("SASL=LOGIN"),
    POP3_CAPA("CAPA"),
    POP3_UIDL("UIDL"),
    POP3_PIPELINING("PIPELINING"),
    POP3_STLS("STLS"),

    SMTP_AUTHPLAIN("AUTH=PLAIN"),
    SMTP_AUTHLOGIN("AUTH=LOGIN"),
    SMTP_STARTTLS("STARTTLS"),
    SMTP_8BITMIME("8BITMIME");

    private final String serverCapability;

    private ServerCapability(String serverCapability) {
        this.serverCapability = serverCapability;
    }

    public String getServerCapability() {
        return serverCapability;
    }

    public static ServerCapability getCapabilityFromString(StarttlsType type, String str) {
        String comparison = str;
        for (ServerCapability capability : getImplemented(type)) {
            if (type == StarttlsType.IMAP && comparison.startsWith("250-"))
                comparison = comparison.substring(4, comparison.length());
            // TODO: Comparison in UpperCase|LowerCase?
            if (capability.getServerCapability().equals(comparison))
                return capability;
        }
        return null;
    }

    public static List<ServerCapability> getImplemented(StarttlsType type) {
        List<ServerCapability> list = new LinkedList<ServerCapability>();
        switch (type) {
            case IMAP:
                list.add(IMAP_IMAP4rev1);
                list.add(IMAP_AUTHPLAIN);
                list.add(IMAP_AUTHLOGIN);
                list.add(IMAP_AUTHDISABLED);
                list.add(IMAP_STARTTLS);
                break;
            case POP3:
                list.add(POP3_USERPLAIN);
                list.add(POP3_USERLOGIN);
                list.add(POP3_SASLPLAIN);
                list.add(POP3_SASLLOGIN);
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
        list.add(POP3_USERLOGIN);
        list.add(POP3_SASLPLAIN);
        list.add(POP3_SASLLOGIN);
        list.add(SMTP_AUTHPLAIN);
        list.add(SMTP_AUTHLOGIN);
        return list;
    }

}
