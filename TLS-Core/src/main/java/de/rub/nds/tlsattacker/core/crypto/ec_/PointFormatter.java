/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec_;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.UnparseablePointException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author robert
 */
public class PointFormatter {

    public static byte[] formatToByteArray(Point point, ECPointFormat format) {
        switch (format) {
            case UNCOMPRESSED:
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(0x04);
                int elementLenght = ArrayConverter.bigIntegerToByteArray(point.getX().getModulus()).length;
                try {
                    stream.write(ArrayConverter.bigIntegerToNullPaddedByteArray(point.getX().getData(), elementLenght));
                    stream.write(ArrayConverter.bigIntegerToNullPaddedByteArray(point.getY().getData(), elementLenght));
                } catch (IOException ex) {
                    throw new PreparationException("Could not serialize ec point", ex);
                }
                return stream.toByteArray();
            case ANSIX962_COMPRESSED_CHAR2:
            case ANSIX962_COMPRESSED_PRIME:
            default:
                throw new UnsupportedOperationException("Unnsupported PointFormat: " + format);

        }
    }

    public static Point formatFromByteArray(NamedGroup group, byte[] compressedPoint) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(compressedPoint);
        EllipticCurve curve = CurveFactory.getCurve(group);
        int elementLenght = ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length;
        if (compressedPoint.length == 0) {
            throw new UnparseablePointException("Could not parse point. Point is empty");
        }
        int pointFormat = inputStream.read();
        switch (pointFormat) {
            case 4:
                if (compressedPoint.length != elementLenght * 2 + 1) {
                    throw new UnparseablePointException("Could not parse point. Point needs to be "
                            + (elementLenght * 2 + 1) + " bytes long, but was " + compressedPoint.length + "bytes long");
                }
                byte[] xCoordinate = new byte[elementLenght];
                byte[] yCoordinate = new byte[elementLenght];
                try {
                    inputStream.read(xCoordinate);
                    inputStream.read(yCoordinate);
                } catch (IOException ex) {
                    Logger.getLogger(PointFormatter.class.getName()).log(Level.SEVERE, null, ex);
                }
                return curve.getPoint(new BigInteger(1, xCoordinate), new BigInteger(1, yCoordinate));

            default:
                throw new UnsupportedOperationException("Unnsupported PointFormat: " + pointFormat);

        }
    }
}
