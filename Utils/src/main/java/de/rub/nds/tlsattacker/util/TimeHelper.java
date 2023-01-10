/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.util;

public class TimeHelper {
    private static TimeProvider provider;

    public static long getTime() {
        if (provider == null) {
            provider = new RealTimeProvider();
        }
        return provider.getTime();
    }

    public static void setProvider(TimeProvider provider) {
        TimeHelper.provider = provider;
    }

    private TimeHelper() {}
}
