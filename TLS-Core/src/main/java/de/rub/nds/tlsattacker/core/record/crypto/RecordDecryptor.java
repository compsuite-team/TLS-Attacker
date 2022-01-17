/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private RecordNullCipher nullCipher;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
        nullCipher = RecordCipherFactory.getNullCipher(context);
    }

    @Override
    public void decrypt(Record record) {
        LOGGER.debug("Decrypting Record");
        RecordCipher recordCipher;
        if (context.getChooser().getSelectedProtocolVersion().isDTLS() && record.getEpoch() != null
            && record.getEpoch().getValue() != null) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        record.prepareComputations();
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
        if (version == null || !version.isDTLS()) {
            record.setSequenceNumber(BigInteger.valueOf(recordCipher.getState().getReadSequenceNumber()));
        }

        try {
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()
                || record.getContentMessageType() != TlsMessageType.CHANGE_CIPHER_SPEC) {
                recordCipher.decrypt(record);
                recordCipher.getState().increaseReadSequenceNumber();
            } else {
                LOGGER.debug("Skipping decryption for legacy CCS");
                new RecordNullCipher(context, recordCipher.getState()).decrypt(record);
            }
        } catch (CryptoException | ParserException ex) {
            LOGGER.warn("Could not decrypt Record. Using NullCipher instead", ex);
            try {
                nullCipher.decrypt(record);
            } catch (CryptoException ex1) {
                LOGGER.warn("Could not decrypt Record with null cipher", ex1);
            }
        }
    }
}
