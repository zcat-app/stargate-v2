# I2P port admission

Before publishing a waiting device's tunnel configuration, the proxy probes its
port on the configured router address. Admission requires a recognized
connection-refusal result; a successful connection, timeout, or unrecognized
failure leaves the device waiting. Existing active connections are not probed or
evicted by this admission check.

The current classifier recognizes the Linux JDK message
`Connection refused (connect failed)`. Java does not expose the underlying errno through this
exception, and exception messages can vary by JDK implementation or locale.
Another runtime may therefore leave a port waiting even when it is available.
The probe is a point-in-time observation, not a reservation: another process can
claim the port later, and a refusal does not prove that no listener exists
behind a filter.

The lifecycle worker probes waiting ports serially, with up to a 100 ms connect
timeout per port. Many simultaneously unresponsive ports can delay other
lifecycle updates. The connect timeout does not bound hostname resolution or
the total worker delay; this is an availability limitation of the current guard.
