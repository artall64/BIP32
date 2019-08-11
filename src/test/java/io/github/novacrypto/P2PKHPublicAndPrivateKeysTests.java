/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Original source: https://github.com/NovaCrypto/BIP32
 *  You can contact the authors via github issues.
 */

package io.github.novacrypto;

import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.Network;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58AddressEqual;
import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.hashing.Sha256.sha256Twice;
import static org.junit.Assert.assertEquals;

public final class P2PKHPublicAndPrivateKeysTests {

    @Test
    public void m_44h_2h_0h_0_1_litecoin_mainnet() {
        // You can check that with https://iancoleman.io/bip39/
        String givenSeed = "velvet eager lunar best peace jaguar tenant flavor render evoke loyal giggle";
        String givenPath = "m/44'/2'/0'/0/1";
        byte litecoinWifPrefix = (byte) 0xB0; //  0x80 for bitcoin

        String expectedAddress = "LV9ievjvooUhxjFrYUXC9HTo78GwVTUUbC";
        String expectedPublicKey = "0343b4760db78f3360520f17e296a627b13ae923f91aa30d26af7c9858063ac6fb";
        String expectedPrivateKey = "T9PeTUcwrDiJ2YvpXrwHSEqCW3STifbsDz6vmGNAGzKt7ZGq2wda";

        assertAddressAndKeys(
                expectedAddress,
                expectedPublicKey,
                expectedPrivateKey,
                // Given params
                givenSeed,
                givenPath,
                Litecoin.MAIN_NET,
                litecoinWifPrefix
        );
    }

    // Helper to simplify checks using https://iancoleman.io/bip39/ as a reference
    private String PrivateKeyToWif(byte[] privateKeyBytes, byte wifPrefix) {

        byte[] tmp = new byte[34];
        tmp[0] = wifPrefix; // 0x80 or 0xB0 for bitcoin
        System.arraycopy(privateKeyBytes, 0, tmp, 1, 32);
        tmp[33] = (byte) 0x01; // Compressed address
        byte[] checksum = sha256Twice(tmp);

        byte[] extendedWithChecksum = new byte[38];
        System.arraycopy(tmp, 0, extendedWithChecksum, 0, 34);
        System.arraycopy(checksum, 0, extendedWithChecksum, 34, 4);

        return base58Encode(extendedWithChecksum);
    }

    private void assertAddressAndKeys(
            final String expectedAddress,
            final String expectedPublicKey,
            final String expectedPrivateKeyWif,
            final String mnemonic,
            final String derivationPath,
            final Network network,
            final byte wifPrefix) {

        byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");
        ExtendedPrivateKey xPrv = ExtendedPrivateKey.fromSeed(seed, network);

        ExtendedPrivateKey privateKey = xPrv.derive(derivationPath);
        byte[] privateKeyBytes = privateKey.GetPrivateKeyBytes();

        // Use this if you need to look at bytes
        // String privateKeyHex = Hex.toHex(privateKeyBytes);

        String wif = PrivateKeyToWif(privateKeyBytes, wifPrefix);
        assertBase58KeysEqual(expectedPrivateKeyWif, wif);

        ExtendedPublicKey publicKey = privateKey.neuter();
        byte[] publicKeyBytes = publicKey.getPublicKeyBytes();
        String publicKeyHex = Hex.toHex(publicKeyBytes);

        assertEquals("Public key doesn't match", expectedPublicKey, publicKeyHex);

        String address = publicKey.p2pkhAddress();
        assertBase58AddressEqual(expectedAddress, address);
    }
}
