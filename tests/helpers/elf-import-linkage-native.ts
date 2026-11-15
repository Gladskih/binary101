import { execFileSync } from "node:child_process";
import { join } from "node:path";

export const buildElfImportLinkageSamples = (directory: string): string[] => {
  const target = execFileSync("wsl.exe", ["--exec", "wslpath", "-a", directory],
    { encoding: "utf8" }).trim();
  return [
    { name: "lazy", flags: ["-Wl,-z,lazy"] },
    { name: "now", flags: ["-Wl,-z,now"] },
    { name: "no-plt", flags: ["-fno-plt", "-Wl,-z,now"] },
    { name: "ibt", flags: ["-fcf-protection=branch", "-Wl,-z,ibtplt", "-Wl,-z,lazy"] }
  ].map(({ name, flags }) => {
    execFileSync("wsl.exe", ["--exec", "cc", "-O0", "-g", "-fPIE", "-pie", "-Wl,-z,relro",
      ...flags, "-x", "c", "-", "-o", `${target}/${name}.elf`], {
      input: "#include <stdio.h>\n" +
        "int main(void) { return puts(\"binary101 linkage fixture\") < 0; }\n"
    });
    return join(directory, `${name}.elf`);
  });
};
