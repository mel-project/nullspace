# Style guide

## Async combinators

Avoid tokio macros for async combinators. Prefer function-based combinators from crates like futures-concurrency.

## Calling async from sync

Strongly prefer pollster's `block_on()` unless you have a good reason to use, say, the tokio specific block_on.

## Blocking in egui

When in egui, it's actually *fine* to block on the render thread on an RPC call using `.block_on()` from pollster, **as long as the call never touches the network or otherwise takes an unbounded amount of time**. And most InternalProtocol RPC calls do not touch the network, but merely load data from a small SQLite database that is almost certainly already in the page cache.

This is doubly so if the RPC call is in a `use_memo` or any other construct that avoids calling it every single render.

## Docs maintenance

Keep `docs/_sidebar.md` in sync with the docs. When adding, removing, or renaming doc pages, update the sidebar accordingly.

## cargo check

Always run cargo check after making significant changes to make sure things compile.