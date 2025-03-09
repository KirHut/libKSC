/***********************************************************************************************************************
** The KirHut Security Center Library
** TestCipherUnicorn.cpp
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

#include "ksc/cipherunicorn.hpp"

#include <QObject>
#include <QTest>

using namespace KirHut;
using namespace KirHut::KSC;

class TestCipherUnicorn : public QObject
{
    Q_OBJECT

private slots:
    void identityTest();
};

void TestCipherUnicorn::identityTest()
{
    Unicorn::A a;
    QVERIFY(true);
}

QTEST_MAIN(TestCipherUnicorn)
#include "TestCipherUnicorn.moc"
