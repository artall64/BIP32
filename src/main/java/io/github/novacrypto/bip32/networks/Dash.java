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

package io.github.novacrypto.bip32.networks;

import io.github.novacrypto.bip32.Network;

public enum Dash implements Network {
    MAIN_NET {
        @Override
        public int getPrivateVersion() {
            return 0x02fe52cc;
        }

        @Override
        public int getPublicVersion() {
            return 0x02fe52f8;
        }

        @Override
        public byte p2pkhVersion() {
            return 0x4C;
        }

        @Override
        public byte p2shVersion() {
            return 0x10;
        }
    }    
}