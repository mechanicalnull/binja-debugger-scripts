# Binary Ninja Debugger Scripts

Having a scriptable debugger is a really cool thing, and integrating it with
your favorite disassembler/RE tools is even better.  This repo shares some
ideas for things to do with
[Binary Ninja's debugger](https://github.com/Vector35/debugger).

## Disclaimer

All of these are proof-of-concept, if they work (or don't), I appreciate
feedback and pull requests, but they're provided as-is. Enjoy!

## Notes

- These are written for Python3 with typing.
- Naturally, these scripts depend on having the debugger module importable.
- It may make sense to copy the ones you like into your debugger directory.
- The scripts are designed to be imported, but each has a standalone usage to
  allow demonstration/testing of the idea. 

These scripts use a DebugAdapter for most of the debugging bits, so if you're
interested in trying out some of the functions interactively, you can access
the debug adapter for the active view in the UI via the Python Console:

```python
import debugger
debug_state = debugger.get()
dbg = debug_state.adapter
```

Note that these scripts try to rebase intelligently, but that's not really
supported in the GUI. It's easy enough to rebase addresses manually, but it
would've muddied the code a bit.

