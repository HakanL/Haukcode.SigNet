using System.Threading.Tasks;

namespace Haukcode.SigNet.Internal;

/// <summary>
/// Sits between HighPerfComm's receive loop and the application's channel writer. The receive
/// loop only parses datagrams when it has a writer, and polls must be parsed even for a client
/// without one, so the base class always gets this relay. Its lock also serializes deliveries
/// from the receive thread with the sync-timeout flushes from the housekeeping timer, and guards
/// the receive-side stream and sync state.
/// </summary>
internal sealed class DeliveryRelay
{
    private readonly Func<ReceiveDataPacket, Task>? writer;

    private DeliveryRelay(Func<ReceiveDataPacket, Task>? writer)
    {
        this.writer = writer;
    }

    public object Lock { get; } = new();

    public static Func<ReceiveDataPacket, Task> Create(Func<ReceiveDataPacket, Task>? writer, out DeliveryRelay relay)
    {
        relay = new DeliveryRelay(writer);

        return relay.Deliver;
    }

    public Task Deliver(ReceiveDataPacket packet)
    {
        lock (Lock)
        {
            DeliverLocked(packet);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Deliver while already holding <see cref="Lock"/>. Waits for the writer: the packet's
    /// buffers are reused as soon as this returns.
    /// </summary>
    public void DeliverLocked(ReceiveDataPacket packet)
    {
        if (this.writer == null)
            return;

        var task = this.writer(packet);
        if (!task.IsCompleted)
            task.GetAwaiter().GetResult();
    }
}
