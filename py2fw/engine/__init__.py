"""Deterministic policy evaluation engine.

Answers "given a packet (source, destination, protocol, port), which rule wins
and what does it do" using first-match semantics over the compiled IR. Powers
``simulate``, ``explain`` and semantic policy diffing.
"""
