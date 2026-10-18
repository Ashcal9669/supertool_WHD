"""MLO evidence: per-link state, association epochs, packet paths, RX evidence, firmware identity.

Everything here is derived from observations (kernel events, tracepoints, debugfs reads, packet captures). Nothing is
inferred across an evidence gap: where data is missing the value is UNKNOWN and the gap says which collector would
have supplied it.
"""
