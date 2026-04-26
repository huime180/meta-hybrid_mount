import { describe, expect, it } from "vitest";
import { normalizeModuleMode } from "./moduleMode";

describe("normalizeModuleMode", () => {
  it("returns magic when mode is magic", () => {
    expect(normalizeModuleMode("magic")).toBe("magic");
  });

  it("returns kasumi when mode is kasumi", () => {
    expect(normalizeModuleMode("kasumi")).toBe("kasumi");
  });

  it("returns ignore when mode is ignore", () => {
    expect(normalizeModuleMode("ignore")).toBe("ignore");
  });

  it("falls back to overlay for unknown mode", () => {
    expect(normalizeModuleMode("unknown")).toBe("overlay");
  });
});
