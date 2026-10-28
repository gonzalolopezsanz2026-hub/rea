import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const digest = async (path) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");

const FIXTURE_SOURCES = {
  "Helper.java":
    'package dependency; public class Helper { public static String label() { return "helper"; } }',
  "Suffix.java":
    'package dependency; public class Suffix { public static String label() { return "suffix"; } }',
  "Plain.java":
    'public class Plain { public static String choose(int value) { return value > 0 ? "REA_JVM_FIXTURE-positive" : "REA_JVM_FIXTURE-negative"; } }',
  "Probe.java":
    'package fixture; import dependency.Helper; import dependency.Suffix; import java.util.function.Supplier; public class Probe { public static String choose(int value) { Supplier<String> label = () -> "REA_JVM_FIXTURE:" + Helper.label() + Suffix.label(); return value > 0 ? label.get() : new Nested().label(); } public static class Nested { public String label() { return "nested"; } } }',
  "Unselected.java":
    'package fixture; public class Unselected { public static String label() { return "UNSELECTED_FIXTURE"; } }',
};

export async function buildJvmFixture(directory, environment) {
  const tool = (name) =>
    environment.JAVA_HOME === undefined
      ? name
      : join(
          environment.JAVA_HOME,
          "bin",
          process.platform === "win32" ? `${name}.exe` : name,
        );
  let javacVersion;
  try {
    const version = await execute(tool("javac"), ["-version"], {
      env: environment,
    });
    javacVersion = `${version.stdout}${version.stderr}`.trim();
    await execute(tool("jar"), ["--version"], { env: environment });
  } catch (cause) {
    throw new Error(
      "verify:jvm requires a full JDK: set JAVA_HOME or add javac and jar to PATH; REA does not install it",
      { cause },
    );
  }
  const source = join(directory, "source");
  const classes = join(directory, "classes");
  const dependencies = join(directory, "dependencies");
  await Promise.all([source, classes, dependencies].map((path) => mkdir(path)));
  for (const [name, text] of Object.entries(FIXTURE_SOURCES))
    await writeFile(join(source, name), `${text}\n`);
  await execute(
    tool("javac"),
    [
      "--release",
      "17",
      "-g",
      "-d",
      dependencies,
      join(source, "Helper.java"),
      join(source, "Suffix.java"),
    ],
    { env: environment },
  );
  const classpath = [];
  for (const name of ["Helper", "Suffix"]) {
    const path = join(directory, `${name}.jar`);
    await execute(
      tool("jar"),
      [
        "--create",
        "--file",
        path,
        "-C",
        dependencies,
        `dependency/${name}.class`,
      ],
      { env: environment },
    );
    classpath.push(path);
  }
  await execute(
    tool("javac"),
    [
      "--release",
      "17",
      "-g",
      "-classpath",
      classpath.join(delimiter),
      "-d",
      classes,
      ...["Plain.java", "Probe.java", "Unselected.java"].map((name) =>
        join(source, name),
      ),
    ],
    { env: environment },
  );
  const jarPath = join(directory, "fixture.jar");
  await execute(
    tool("jar"),
    ["--create", "--file", jarPath, "-C", classes, "fixture"],
    { env: environment },
  );
  const classPath = join(classes, "Plain.class");
  const caseFixture = await buildCaseFixture(tool, directory, environment);
  const inputs = await Promise.all(
    [classPath, jarPath, caseFixture.casePath, ...classpath].map(
      async (path) => ({
        path,
        sha256: await digest(path),
      }),
    ),
  );
  return {
    classPath,
    jarPath,
    classpath,
    inputs,
    javacVersion,
    ...caseFixture,
  };
}

async function buildCaseFixture(tool, directory, environment) {
  const casePath = join(directory, "case.jar");
  const arguments_ = ["--create", "--file", casePath];
  for (const [name, marker] of [
    ["CaseProbe", "UPPER"],
    ["caseprobe", "LOWER"],
  ]) {
    const root = join(directory, `case-${marker}`);
    await mkdir(root);
    const source = join(root, `${name}.java`);
    await writeFile(
      source,
      `package fixture; public class ${name} { public String marker() { return "REA_JVM_FIXTURE_${marker}"; } }`,
    );
    await execute(tool("javac"), ["--release", "17", "-d", root, source], {
      env: environment,
    });
    arguments_.push("-C", root, `fixture/${name}.class`);
  }
  await execute(tool("jar"), arguments_, { env: environment });
  await writeFile(join(directory, "CaseSensitivity"), "owned filesystem probe");
  let caseSensitive = false;
  try {
    await readFile(join(directory, "casesensitivity"));
  } catch (cause) {
    if (cause.code !== "ENOENT") throw cause;
    caseSensitive = true;
  }
  return { casePath, caseSensitive };
}
