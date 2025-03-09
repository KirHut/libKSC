/***********************************************************************************************************************
** The KirHut Security Center Library
** ksc/signalemitter.hpp
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

#include <QObject>

namespace KirHut::KSC
{

/*!
 * Extremely Simple QObject that just emits a signal when it is activated.
 *
 * It seems like an odd missing feature in Qt that there is no object that literally just emits a signal when you want
 * it to. The signals and slots mechanism is very powerful, and allows for thread-safe event-based object communication,
 * but for some reason there is no QObject that literally just emits a signal when you want it to emit a signal. There
 * are many use cases where you want to emit a signal from an object that is not a QObject, and that object not being a
 * QObject is usually a deliberate engineering choice. To facilitate signal emission from these objects, this extremely
 * simple class exists.
 *
 * All it does is emit the activated() signal when the activate() method is called. The activate() method is a slot
 * itself in case this is necessary, though if you have an object that can emit a signal already you probably have no
 * need for a SignalEmitter. The activate() method may nonetheless be called by non QObject classes. An additional
 * intActivate() method and intActivated() signal are included to allow communication of values.
 *
 * Threading is handled entirely by the Qt signals and slots mechanism, no effort was made to make this class thread
 * safe in any way!
 */
class SignalEmitter : public QObject
{
    Q_OBJECT

public:
    /*!
     * Create a SignalEmitter.
     *
     * The passed in \p parent follows the standard QObject parent/child relationship, so this can be useful to ensure
     * that a SignalEmitter is deleted at the end of the useful life of another QObject.
     *
     * \param parent The parent QObject of this object, using the standard Qt parent/child relationship.
     * \throws std::bad_alloc If allocating memory in the QObject constructor fails.
     */
    explicit SignalEmitter(QObject *parent = nullptr);

public slots:
    /*!
     * Method to cause this SignalEmitter to emit the activated() signal.
     *
     * Call this method when you want to emit the activated() signal to the listeners for that signal. You may connect
     * slots to the activated() signal using a QueuedConnection to ensure the connection is thread safe.
     */
    void activate() noexcept;

    /*!
     * Method to cause this SignalEmitter to emit the intActivated() signal.
     *
     * Call this method when you want to emit the intActivated() signal with the passed in val to the listeners for that
     * signal. You may connect slots to the intActivated() signal using a QueuedConnection to ensure the connection is
     * thread safe.
     *
     * \param val The integer to send to the slots listening to the intActivated() signal.
     */
    void intActivate(int val) noexcept;

signals:
    /*!
     * Signal emitted when the activate() method is called.
     *
     * Connect slots to this signal to use this SignalEmitter for communicating with other QObjects.
     */
    void activated();

    /*!
     * Signal emitted when the intActivate() method is called.
     *
     * Sometimes it is useful to send an integer with a signal, so this exists as well. There are, of course, an
     * unlimited number of possible arguments that can be sent by a signal, but for incredibly generic values like int,
     * they are provided on the base SignalEmitter class.
     *
     * \param val An integer to send to the slots listening to this signal.
     */
    void intActivated(int val);
};

} // namespace KirHut::KSC
