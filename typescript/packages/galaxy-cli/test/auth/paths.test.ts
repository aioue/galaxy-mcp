import { describe, expect, it } from "vitest";
import { configDir, hostsFile } from "../../src/auth/paths";

describe("configDir", () => {
  it("prefers GXY_CONFIG_DIR, then XDG_CONFIG_HOME, then ~/.config", () => {
    expect(configDir({ GXY_CONFIG_DIR: "/x", XDG_CONFIG_HOME: "/xdg" }, "/home/u")).toBe("/x");
    expect(configDir({ XDG_CONFIG_HOME: "/xdg" }, "/home/u")).toBe("/xdg/gxy");
    expect(configDir({}, "/home/u")).toBe("/home/u/.config/gxy");
  });
  it("treats empty and relative values as unset", () => {
    expect(configDir({ GXY_CONFIG_DIR: "", XDG_CONFIG_HOME: "rel" }, "/home/u")).toBe("/home/u/.config/gxy");
  });
});

describe("hostsFile", () => {
  it("is hosts.yml in the config directory", () => {
    expect(hostsFile("/x/gxy")).toBe("/x/gxy/hosts.yml");
  });
});
