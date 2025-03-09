/***********************************************************************************************************************
** The KirHut Security Center Library
** ksc/cipherunicorn.hpp
** Copyright © KirHut Software Company
**
** This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
** Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
** later version.
**
** This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
** details.
**
** You should have received a copy of the GNU Affero General Public License along with this program.  If not, see
** <http://www.gnu.org/licenses/>.
***********************************************************************************************************************/
#pragma once

#include "kh/base.hpp"

namespace KirHut::KSC
{

namespace Unicorn
{

class A
{
public:
    typedef KirHut::array<byte, 16> Block;
    typedef KirHut::array<byte, 32> Secret;
    typedef KirHut::array<byte, 288> Key;

    A();
    A(Key key);
	void setKey(Key const &toCopy);

	static Key makeKey(Secret const &secret);

    void encrypt(byte const *source, byte *dest, size_t length);

    void encryptBlock(byte const *source, byte *dest);
	void encryptBlock(byte *block);
	void encryptBlock(Block &block);

	void decryptBlock(byte const *source, byte *dest);
	void decryptBlock(byte *data);
	void decryptBlock(Block &block);
};

class B
{
public:

};

} // namespace Unicorn

} // namespace KirHut::KSC
