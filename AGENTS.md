# Agents guide

## Ask the user when unsure

Your task is to faithfully do as the user tell you to. This means that if the user is unclear or confused about something, you need to clarify, rather than attempt to be creative and "guess".

## Async combinators

Avoid tokio macros for async combinators. Prefer function-based combinators from crates like futures-concurrency.

## Calling async from sync

Strongly prefer pollster's `block_on()` unless you have a good reason to use, say, the tokio specific block_on.

## Blocking in egui

When in egui, it's actually *fine* to block on the render thread on an RPC call using `.block_on()` from pollster, **as long as the call never touches the network or otherwise takes an unbounded amount of time**. And most InternalProtocol RPC calls do not touch the network, but merely load data from a small SQLite database that is almost certainly already in the page cache.

This is doubly so if the RPC call is in a `use_memo` or any other construct that avoids calling it every single render.

## egui_hooks use_state

`use_state` is already keyed by the current `ui.id()` and hook index. The `deps` argument only forces re-initialization *within the same widget id* when it changes. In most cases, pass `()` for deps. Only use deps when you explicitly want to reset state within a single widget instance. For distinct state scopes, prefer `ui.push_id(...)` or `use_hook_as(...)` rather than encoding IDs into deps.

## egui use_gbox

`use_gbox` follows the same widget-id and hook-index scoping rules as `use_state`, so conditional hook branches still need distinct ids (`ui.push_id(...)`, etc.) when they represent different state scopes.

Prefer `use_gbox` when you want a widget-owned handle that is cheap to copy into closures or async tasks, or when the state itself is a long-lived object such as a task handle, scroller, or other nontrivial owned value. Prefer `use_state`/`State`/`Var` for normal form state that is edited inline by egui widgets like `TextEdit`, `Checkbox`, and selection controls.

## Niche crate notes

When you learn something non-obvious about a niche crate while developing, add a short note about it to this file so the knowledge accumulates. This especially applies to crates like `egui_taffy`, `egui_flex`, and `egui_hooks`, where the surprising parts are usually layout or state-model details that are easy to rediscover the hard way.

## egui_taffy

`egui_taffy::tui(...)` does not default to "fill the available parent width". Its default available space is `MinContent` on both axes, so a flex row will happily shrink-wrap unless you explicitly give it a width budget.

`reserve_available_width()` gives the taffy tree a definite width budget, but that alone does not make the root node itself stretch to fill that width. If you want `flex_grow` on a child to actually consume remaining horizontal space and push trailing siblings to the far edge, the root flex node often also needs an explicit width such as `size.width = Dimension::Percent(1.0)`.

In other words: for `egui_taffy` row layouts, "the container knows how much width is available" and "the container itself fills that width" are separate things. If a supposedly growing middle column is not growing, check both.

This is exactly the kind of layout where `egui_taffy` helps: fixed leading item, growing middle item, fixed trailing item. But it only behaves like flexbox after the parent width contract is made explicit.

`egui_taffy` also has a text-wrapping pitfall documented upstream: in dynamic layouts, wrapped egui text may try to use as little width as possible and end up wrapping into a one-character-wide vertical column. When a trailing text label in a taffy row suddenly stacks letters vertically, assume this issue first.

The documented workarounds are:
- give the text element a width or minimum width, or otherwise make it fill the parent width
- set an explicit wrap mode for that element, such as `egui::TextWrapMode::Truncate`
- or disable wrapping for that context with `TextWrapMode::Extend`

For short trailing status/reason labels in horizontal rows, prefer `Truncate` or `Extend` over default wrapping. That avoids the pathological "one letter per line" result.

## egui_flex

Use `egui_flex` sparingly and prefer plain egui layout primitives unless you actually need grow/shrink behavior.

For row layouts that are supposed to consume the full available width, `w_full()` is usually required; otherwise the flex container may size to its contents.

Nested flex containers need to go through `add_flex` or `show_in` so the parent can measure them correctly.

Only one item in a non-wrapping flex row should use `shrink()`.

If a flex item's text or selected state changes its intrinsic width across frames, set a stable `content_id(...)` so it gets remeasured promptly.

## nullspace-client group state

In `nullspace-client`, local group state should advance through the normal receive/poll path rather than being written through immediately after a successful send. Local insertion of outgoing thread events is still allowed for UI presentation. Group ban and unban propagate by submitting a new GBK rotation.

## Docs maintenance

Keep `docs/SUMMARY.md` in sync with the docs. When adding, removing, or renaming doc pages, update the summary accordingly.

When editing code, edit the documentation **MINIMALLY** to fix any documentation that contradicts the code.

## Documentation rules

- Keep docs implementation-neutral; do not mention Rust type names.
- When referring to other doc files, use Markdown links (e.g. `[events](events.md)`).
- When describing BCS-encoded structures, use tuple/list notation (e.g. `[a, b, c]`), since field names are not preserved.
- When documenting flows, prefer clear pseudocode that enables clean-room implementations.

## cargo check

Always run cargo check after making significant changes to make sure things compile.

## module/mod.rs vs module.rs

use module/mod.rs when *all* it does is reexport things, but use module.rs when the root has its own logic and its submodules are    
helpers for this logic.         

## Visibility style

Prefer module structure that keeps private things private without restricted visibilities.

As a style rule, treat `pub(crate)` and `pub(super)` as anti-patterns. If something should not be visible outside a module boundary, reorganize the modules so plain `pub` on the intended interface is sufficient and internal helpers remain private by normal module visibility.
