import { describe, it, expect } from "vitest";
import { cn } from "../utils";

// Smoke test for the `cn()` classname combiner. The web UI uses this in
// every shadcn-style component, so a regression in clsx/tailwind-merge
// would silently break styling across the app. The test pins down the
// three behaviors we actually depend on:
//
//   1. passing nothing returns "" (no spurious "undefined" classes)
//   2. falsy values are filtered out (so `cn("a", cond && "b")` works)
//   3. conflicting tailwind utilities are resolved to the last one
describe("cn", () => {
  it("returns an empty string for no inputs", () => {
    expect(cn()).toBe("");
  });

  it("filters out falsy values", () => {
    expect(cn("foo", false, null, undefined, 0, "bar")).toBe("foo bar");
  });

  it("merges conflicting tailwind utilities to the last one", () => {
    // tailwind-merge resolves p-2 vs p-4 by keeping the last one.
    expect(cn("p-2", "p-4")).toBe("p-4");
  });
});
