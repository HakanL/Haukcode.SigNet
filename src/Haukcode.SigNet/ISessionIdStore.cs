namespace Haukcode.SigNet;

/// <summary>
/// Non-volatile storage for the device's Sig-Net-Session-ID, implemented by the host application.
/// The library persists nothing itself.
///
/// Spec 8.3: before its first authenticated packet of every run, and whenever a sequence counter
/// wraps, a device increments the session id and saves it to non-volatile storage. The client
/// calls <see cref="LoadSessionId"/> once, then <see cref="SaveSessionId"/> with the new value
/// before anything is sent. The session id belongs to the device (its TUID), not to one client:
/// two clients sharing a TUID must share the store.
///
/// Offboarding (spec 7.7) keeps the session id, except when recovering from exhaustion, where the
/// host resets it to zero together with new keys.
/// </summary>
public interface ISessionIdStore
{
    /// <summary>
    /// The last saved session id, or 0 on a device that has never sent.
    /// </summary>
    uint LoadSessionId();

    /// <summary>
    /// Durably save the new session id before returning (flush to disk or flash). Throw if it
    /// cannot be saved; the client will not send with a session id that is not persisted.
    /// </summary>
    void SaveSessionId(uint sessionId);
}

/// <summary>
/// The session id reached 0xFFFFFFFF (spec 8.3 "Session ID Overflow"). The device must stop
/// sending authenticated packets until it is offboarded and rekeyed, which resets the id to zero.
/// </summary>
public class SessionIdExhaustedException : InvalidOperationException
{
    public SessionIdExhaustedException()
        : base("The Sig-Net session id is exhausted (0xFFFFFFFF); offboard and rekey the device to reset it (spec 8.3, 7.7)")
    {
    }
}
