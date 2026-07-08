"""replay — node-I/O JSONL recording (record.py) + offline playback (play.py).

The recorder (PA-7/PS-3) captures each LangGraph node update (stream_mode='updates')
as a secret-free, byte-identical JSONL line. The player (H-J) reconstructs the tick
timeline offline (no testbed, stdlib) so a reviewer can drive the Viewer/Verifier from
``run.jsonl`` alone. This package is core-side (recording pipeline); the out-of-graph
Verifier consumes the JSONL and never imports it or core.
"""
